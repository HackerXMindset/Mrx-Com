package org.koitharu.kotatsu.scrobbling.comick.data

import android.content.Context
import android.util.Base64
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.FormBody
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okio.IOException
import org.json.JSONObject
import org.koitharu.kotatsu.R
import org.koitharu.kotatsu.core.db.MangaDatabase
import org.koitharu.kotatsu.core.network.BaseHttpClient
import org.koitharu.kotatsu.parsers.util.await
import org.koitharu.kotatsu.parsers.util.json.getStringOrNull
import org.koitharu.kotatsu.scrobbling.comick.asHidToLong
import org.koitharu.kotatsu.scrobbling.comick.comickStatus
import org.koitharu.kotatsu.scrobbling.comick.COMICK_TOKEN_EXPIRY_KEY
import org.koitharu.kotatsu.scrobbling.comick.toHid
import org.koitharu.kotatsu.scrobbling.common.data.ScrobblerRepository
import org.koitharu.kotatsu.scrobbling.common.data.ScrobblerStorage
import org.koitharu.kotatsu.scrobbling.common.data.ScrobblingEntity
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerManga
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerMangaInfo
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerService
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerType
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerUser
import java.security.MessageDigest
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

private const val OAUTH_BASE_URL = "https://comick.dev/api/auth/oauth2"
private const val API_BASE_URL = "https://api.comick.dev/integrations/v1"
private const val REDIRECT_URI = "io.github.kotatsuredo.kotatsu://comick-auth"
private const val COMICK_SCOPE = "library:read library:write offline_access"
private const val OAUTH_STATE_KEY = "comick_oauth_state"
private const val CODE_VERIFIER_KEY = "comick_code_verifier"
private const val CLIENT_ID_PLACEHOLDER = "REPLACE_WITH_COMICK_OAUTH_CLIENT_ID"
private val JSON_MEDIA_TYPE = "application/json; charset=utf-8".toMediaType()

/**
 * Comick OAuth and integrations API adapter.
 *
 * HID conversion, PKCE, resource URL, scopes and request shapes follow
 * Mihon's Comick tracker implementation, adapted to Kotatsu's ScrobblerRepository.
 */
@Singleton
class ComickRepository @Inject constructor(
	@ApplicationContext context: Context,
	@ScrobblerType(ScrobblerService.COMICK) private val okHttp: OkHttpClient,
	@BaseHttpClient private val baseClient: OkHttpClient,
	@ScrobblerType(ScrobblerService.COMICK) private val storage: ScrobblerStorage,
	private val db: MangaDatabase,
) : ScrobblerRepository {

	private val clientId = context.getString(R.string.comick_clientId)

	override val oauthUrl: String
		get() {
			check(clientId.isNotBlank() && clientId != CLIENT_ID_PLACEHOLDER) {
				"Comick OAuth is not configured. Register an app at https://comick.dev/developers/apps and set comick_clientId."
			}
			val state = randomUrlSafe(16)
			val verifier = randomUrlSafe(32)
			storage[OAUTH_STATE_KEY] = state
			storage[CODE_VERIFIER_KEY] = verifier
			val challenge = Base64.encodeToString(
				MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII)),
				Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING,
			)
			return "$OAUTH_BASE_URL/authorize".toHttpUrl().newBuilder()
				.addQueryParameter("response_type", "code")
				.addQueryParameter("client_id", clientId)
				.addQueryParameter("redirect_uri", REDIRECT_URI)
				.addQueryParameter("scope", COMICK_SCOPE)
				.addQueryParameter("resource", API_BASE_URL)
				.addQueryParameter("state", state)
				.addQueryParameter("code_challenge", challenge)
				.addQueryParameter("code_challenge_method", "S256")
				.build()
				.toString()
		}

	override val isAuthorized: Boolean
		get() = storage.accessToken != null

	override val cachedUser: ScrobblerUser?
		get() = storage.user

	override fun verifyOAuthState(state: String?): Boolean {
		val expectedState = storage[OAUTH_STATE_KEY]
		return !state.isNullOrBlank() && !expectedState.isNullOrBlank() && state == expectedState
	}

	override suspend fun authorize(code: String?) {
		check(clientId.isNotBlank() && clientId != CLIENT_ID_PLACEHOLDER) {
			"Comick OAuth is not configured. Register an app at https://comick.dev/developers/apps and set comick_clientId."
		}
		val body = FormBody.Builder()
			.add("client_id", clientId)
			.add("resource", API_BASE_URL)
			.apply {
				if (code != null) {
					add("grant_type", "authorization_code")
					add("code", code)
					add("redirect_uri", REDIRECT_URI)
					add("code_verifier", storage[CODE_VERIFIER_KEY]
						?: throw IOException("Comick PKCE verifier was lost. Please sign in again."))
				} else {
					add("grant_type", "refresh_token")
					add("refresh_token", storage.refreshToken
						?: throw IOException("Comick refresh token is missing. Please sign in again."))
				}
			}
			.build()
		val request = Request.Builder()
			.url("$OAUTH_BASE_URL/token")
			.post(body)
			.header("Accept", "application/json")
			.build()
		val json = executeJson(baseClient, request)
		val accessToken = json.getStringOrNull("access_token")
			?: throw IOException("Comick returned no access token")
		val refreshToken = json.getStringOrNull("refresh_token") ?: storage.refreshToken
		val expiresAt = json.optLong("expires_at", 0L)
		if (expiresAt <= 0L) throw IOException("Comick returned an invalid token expiry")
		val scope = json.getStringOrNull("scope").orEmpty()
		if (refreshToken.isNullOrBlank()) {
			throw IOException("Comick must grant offline_access for ongoing synchronization. Please sign in again and enable it.")
		}
		if ("library:write" !in scope.split(Regex("\\s+"))) {
			throw IOException("Comick must grant library:write to add, update and remove library entries.")
		}

		storage.accessToken = accessToken
		storage.refreshToken = refreshToken
		storage[COMICK_TOKEN_EXPIRY_KEY] = expiresAt.toString()
		storage["comick_scope"] = scope
		storage[CODE_VERIFIER_KEY] = null
		storage[OAUTH_STATE_KEY] = null
	}

	override suspend fun loadUser(): ScrobblerUser {
		val json = executeJson(okHttp, Request.Builder().url("$API_BASE_URL/me").get().build())
		val id = json.getString("id")
		val user = ScrobblerUser(
			id = id.toLongOrNull() ?: id.hashCode().toLong(),
			nickname = json.getStringOrNull("username")?.takeIf(String::isNotBlank) ?: id,
			avatar = null,
			service = ScrobblerService.COMICK,
		)
		storage.user = user
		return user
	}

	override fun logout() {
		storage.clear()
	}

	override suspend fun unregister(mangaId: Long) {
		val entity = db.getScrobblingDao().find(ScrobblerService.COMICK.id, mangaId) ?: return
		val hid = entity.targetId.toHid()
		val request = Request.Builder().url(libraryUrl(hid)).delete().build()
		executeNoContent(okHttp, request, notFoundIsSuccess = true)
		db.getScrobblingDao().delete(ScrobblerService.COMICK.id, mangaId)
	}

	override suspend fun findManga(query: String, offset: Int): List<ScrobblerManga> {
		// The Comick integrations endpoint returns one limited search page (as in Mihon).
		// Do not request the same first page repeatedly for Kotatsu's offset-based search UI.
		if (offset > 0) return emptyList()
		val url = "$API_BASE_URL/titles".toHttpUrl().newBuilder()
			.addQueryParameter("q", query.take(100))
			.addQueryParameter("media_type", "manga")
			.addQueryParameter("limit", "20")
			.build()
		val result = executeJson(okHttp, Request.Builder().url(url).get().build())
			.getJSONArray("data")
		return buildList(result.length()) {
			for (index in 0 until result.length()) {
				val item = result.getJSONObject(index)
				val hid = item.getString("hid")
				val title = item.getString("title")
				add(
					ScrobblerManga(
						id = hid.asHidToLong(),
						name = title,
						altName = null,
						cover = item.getStringOrNull("cover_url"),
						url = item.getStringOrNull("url") ?: "https://comick.dev/comic/$hid",
						isBestMatch = title.equals(query, ignoreCase = true),
					),
				)
			}
		}
	}

	override suspend fun getMangaInfo(id: Long): ScrobblerMangaInfo {
		val hid = id.toHid()
		val json = executeJson(okHttp, Request.Builder().url("$API_BASE_URL/titles/$hid").get().build())
			.getJSONObject("data")
		return ScrobblerMangaInfo(
			id = hid.asHidToLong(),
			name = json.getString("title"),
			cover = json.getStringOrNull("cover_url"),
			url = json.getStringOrNull("url") ?: "https://comick.dev/comic/$hid",
			descriptionHtml = json.getStringOrNull("description").orEmpty(),
		)
	}

	override suspend fun createRate(mangaId: Long, scrobblerMangaId: Long) {
		val hid = scrobblerMangaId.toHid()
		val existing = findLibraryEntry(hid)
		if (existing != null) {
			saveRate(existing, mangaId)
			return
		}

		val body = JSONObject()
			.put("status", 5) // Plan to read, matching Mihon's default for a new binding.
			.put("progress", JSONObject.NULL)
			.put("rating", JSONObject.NULL)
			.toString()
			.toRequestBody(JSON_MEDIA_TYPE)
		val request = Request.Builder().url(libraryUrl(hid)).put(body).build()
		executeNoContent(okHttp, request)

		// Comick identifies the library entry by title HID; it has no separate entry ID.
		db.getScrobblingDao().upsert(
			ScrobblingEntity(
				scrobbler = ScrobblerService.COMICK.id,
				id = hid.hashCode(),
				mangaId = mangaId,
				targetId = scrobblerMangaId,
				status = "5",
				chapter = 0,
				comment = null,
				rating = 0f,
			),
		)
	}

	override suspend fun updateRate(rateId: Int, mangaId: Long, chapter: Int) {
		val entity = db.getScrobblingDao().find(ScrobblerService.COMICK.id, mangaId)
			?: throw IllegalStateException("Comick tracking entry for manga $mangaId not found")
		val currentStatus = entity.status?.toIntOrNull()
		val nextStatus = if (currentStatus == 2 || currentStatus == 1) currentStatus else 1
		val body = JSONObject()
			.put("status", nextStatus)
			.put("rating", entity.rating.takeIf { it > 0f }?.let { (it * 10f).toInt() } ?: JSONObject.NULL)
			.put(
				"progress",
				JSONObject().put("number", chapter.coerceAtLeast(0).toString()),
			)
			.toString()
			.toRequestBody(JSON_MEDIA_TYPE)
		val request = Request.Builder().url(libraryUrl(entity.targetId.toHid())).patch(body).build()
		executeNoContent(okHttp, request)

		db.getScrobblingDao().upsert(
			ScrobblingEntity(
				scrobbler = ScrobblerService.COMICK.id,
				id = entity.id,
				mangaId = entity.mangaId,
				targetId = entity.targetId,
				status = nextStatus.toString(),
				chapter = chapter.coerceAtLeast(0),
				comment = null,
				rating = entity.rating,
			),
		)
	}

	override suspend fun updateRate(
		rateId: Int,
		mangaId: Long,
		rating: Float,
		status: String?,
		comment: String?,
	) {
		val entity = db.getScrobblingDao().find(ScrobblerService.COMICK.id, mangaId)
			?: throw IllegalStateException("Comick tracking entry for manga $mangaId not found")
		val body = JSONObject()
			.put("rating", rating.coerceIn(0f, 1f).takeIf { it > 0f }?.let { (it * 10f).toInt() } ?: JSONObject.NULL)
		val apiStatus = comickStatus(status)
		if (apiStatus != null) body.put("status", apiStatus)
		// Comick's library API does not support comments/notes.
		val request = Request.Builder()
			.url(libraryUrl(entity.targetId.toHid()))
			.patch(body.toString().toRequestBody(JSON_MEDIA_TYPE))
			.build()
		executeNoContent(okHttp, request)

		db.getScrobblingDao().upsert(
			ScrobblingEntity(
				scrobbler = ScrobblerService.COMICK.id,
				id = entity.id,
				mangaId = entity.mangaId,
				targetId = entity.targetId,
				status = apiStatus?.toString() ?: entity.status,
				chapter = entity.chapter,
				comment = null,
				rating = rating.coerceIn(0f, 1f),
			),
		)
	}

	private suspend fun findLibraryEntry(hid: String): JSONObject? {
		val response = okHttp.newCall(Request.Builder().url(libraryUrl(hid)).get().build()).await()
		response.use {
			val raw = it.body?.string().orEmpty()
			if (it.code == 404) return null
			if (!it.isSuccessful) throw IOException("Comick library lookup failed (${it.code}): ${raw.take(240)}")
			return JSONObject(raw).getJSONObject("data")
		}
	}

	private suspend fun saveRate(data: JSONObject, mangaId: Long) {
		val hid = data.getString("hid")
		val progress = data.optJSONObject("progress")?.optString("number")?.toDoubleOrNull()?.toInt() ?: 0
		val apiRating = data.opt("rating") as? Number
		val apiStatus = data.getInt("status")
		db.getScrobblingDao().upsert(
			ScrobblingEntity(
				scrobbler = ScrobblerService.COMICK.id,
				id = hid.hashCode(),
				mangaId = mangaId,
				targetId = hid.asHidToLong(),
				status = apiStatus.toString(),
				chapter = progress.coerceAtLeast(0),
				comment = null,
				rating = ((apiRating?.toFloat() ?: 0f) / 10f).coerceIn(0f, 1f),
			),
		)
	}

	private fun libraryUrl(hid: String): String = "$API_BASE_URL/me/library/$hid"

	private suspend fun executeJson(client: OkHttpClient, request: Request): JSONObject =
		withContext(Dispatchers.IO) {
			val response = client.newCall(request).await()
			response.use {
				val raw = it.body?.string().orEmpty()
				if (!it.isSuccessful) {
					throw IOException("Comick request failed (${it.code}): ${raw.take(240)}")
				}
				JSONObject(raw)
			}
		}

	private suspend fun executeNoContent(
		client: OkHttpClient,
		request: Request,
		notFoundIsSuccess: Boolean = false,
	) = withContext(Dispatchers.IO) {
		val response = client.newCall(request).await()
		response.use {
			val raw = it.body?.string().orEmpty()
			if (notFoundIsSuccess && it.code == 404) return@withContext
			if (!it.isSuccessful) {
				throw IOException("Comick request failed (${it.code}): ${raw.take(240)}")
			}
		}
	}

	private fun randomUrlSafe(byteCount: Int): String {
		val bytes = ByteArray(byteCount)
		SecureRandom().nextBytes(bytes)
		return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
	}
}
