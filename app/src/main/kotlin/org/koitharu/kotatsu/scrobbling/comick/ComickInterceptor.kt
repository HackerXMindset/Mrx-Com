package org.koitharu.kotatsu.scrobbling.comick

import android.content.Context
import dagger.hilt.android.qualifiers.ApplicationContext
import okhttp3.FormBody
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okio.IOException
import org.json.JSONObject
import org.koitharu.kotatsu.R
import org.koitharu.kotatsu.core.network.BaseHttpClient
import org.koitharu.kotatsu.scrobbling.common.data.ScrobblerStorage
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerService
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerType
import javax.inject.Inject

private const val OAUTH_BASE_URL = "https://comick.dev/api/auth/oauth2"
private const val RESOURCE_URL = "https://api.comick.dev/integrations/v1"
internal const val COMICK_TOKEN_EXPIRY_KEY = "comick_expires_at"

class ComickInterceptor @Inject constructor(
	@ApplicationContext context: Context,
	@ScrobblerType(ScrobblerService.COMICK) private val storage: ScrobblerStorage,
	@BaseHttpClient private val baseClient: OkHttpClient,
) : Interceptor {

	private val clientId = context.getString(R.string.comick_clientId)
	private val refreshLock = Any()

	override fun intercept(chain: Interceptor.Chain): Response {
		val accessToken = getFreshAccessToken()
		val request = chain.request().newBuilder()
			.header("Authorization", "Bearer $accessToken")
			.header("Accept", "application/json")
			.header("User-Agent", "MRX/Kotatsu-Redo Android tracking integration")
			.build()
		return chain.proceed(request)
	}

	private fun getFreshAccessToken(): String {
		val currentToken = storage.accessToken
			?: throw IOException("Sign in to Comick from Settings → Tracking first")
		if (!isExpiringSoon()) return currentToken

		synchronized(refreshLock) {
			val latestToken = storage.accessToken ?: throw IOException("Comick is no longer connected")
			// Another request may have refreshed credentials while this request waited.
			if (latestToken != currentToken && !isExpiringSoon()) return latestToken
			if (!isExpiringSoon()) return latestToken
			check(clientId.isNotBlank() && !clientId.startsWith("REPLACE_")) {
				"Comick OAuth is not configured. Register an app at https://comick.dev/developers/apps."
			}

			val refreshToken = storage.refreshToken
				?: throw IOException("Comick did not provide a refresh token. Sign in again.")
			val body = FormBody.Builder()
				.add("grant_type", "refresh_token")
				.add("client_id", clientId)
				.add("refresh_token", refreshToken)
				.add("resource", RESOURCE_URL)
				.build()
			val request = Request.Builder()
				.url("$OAUTH_BASE_URL/token")
				.post(body)
				.header("Accept", "application/json")
				.build()

			val response = try {
				baseClient.newCall(request).execute()
			} catch (e: Exception) {
				throw IOException("Could not refresh Comick authorization", e)
			}
			response.use {
				val raw = it.body?.string().orEmpty()
				if (!it.isSuccessful) {
					throw IOException("Comick token refresh failed (${it.code}): ${raw.take(240)}")
				}
				val json = JSONObject(raw)
				val newAccessToken = json.optString("access_token").takeIf { value -> value.isNotBlank() }
					?: throw IOException("Comick returned no access token during refresh")
				val newRefreshToken = json.optString("refresh_token").takeIf { value -> value.isNotBlank() } ?: refreshToken
				val expiresAt = json.optLong("expires_at", 0L).takeIf { it > 0L }
					?: (System.currentTimeMillis() / 1000L + json.optLong("expires_in", 0L))
				if (expiresAt <= 0L) throw IOException("Comick returned an invalid token expiry")

				storage.accessToken = newAccessToken
				storage.refreshToken = newRefreshToken
				storage[COMICK_TOKEN_EXPIRY_KEY] = expiresAt.toString()
				json.optString("scope").takeIf { scope -> scope.isNotBlank() }?.let { scope ->
					storage["comick_scope"] = scope
				}
			}
			return storage.accessToken ?: throw IOException("Comick token refresh did not persist")
		}
	}

	private fun isExpiringSoon(): Boolean {
		val expiresAt = storage[COMICK_TOKEN_EXPIRY_KEY]?.toLongOrNull() ?: return true
		return expiresAt <= (System.currentTimeMillis() / 1000L) + 60L
	}
}
