package org.koitharu.kotatsu.scrobbling.comick.domain

import org.koitharu.kotatsu.core.db.MangaDatabase
import org.koitharu.kotatsu.core.parser.MangaRepository
import org.koitharu.kotatsu.scrobbling.comick.data.ComickRepository
import org.koitharu.kotatsu.scrobbling.common.domain.Scrobbler
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblerService
import org.koitharu.kotatsu.scrobbling.common.domain.model.ScrobblingStatus
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class ComickScrobbler @Inject constructor(
	private val repository: ComickRepository,
	db: MangaDatabase,
	mangaRepositoryFactory: MangaRepository.Factory,
) : Scrobbler(db, ScrobblerService.COMICK, repository, mangaRepositoryFactory) {

	init {
		statuses[ScrobblingStatus.PLANNED] = "5"
		statuses[ScrobblingStatus.READING] = "1"
		// Comick does not expose a distinct re-reading state.
		statuses[ScrobblingStatus.RE_READING] = "1"
		statuses[ScrobblingStatus.COMPLETED] = "2"
		statuses[ScrobblingStatus.ON_HOLD] = "3"
		statuses[ScrobblingStatus.DROPPED] = "4"
	}

	override suspend fun updateScrobblingInfo(
		mangaId: Long,
		rating: Float,
		status: ScrobblingStatus?,
		comment: String?,
	) {
		val entity = db.getScrobblingDao().find(scrobblerService.id, mangaId)
			?: throw IllegalStateException("Tracking entry for manga $mangaId not found")
		repository.updateRate(
			rateId = entity.id,
			mangaId = entity.mangaId,
			rating = rating,
			status = statuses[status],
			comment = comment,
		)
	}
}
