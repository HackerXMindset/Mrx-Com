package org.koitharu.kotatsu.scrobbling.comick

import android.util.Base64
import org.json.JSONObject

/**
 * Comick uses an 8-character base64url HID while Kotatsu's existing tracking
 * model stores remote manga IDs as Longs. This is the reversible 48-bit mapping
 * used by Mihon's Comick tracker; do not replace it with hashCode().
 */
internal fun String.asHidToLong(): Long {
	require(length == 8) { "Comick HID must be 8 characters: $this" }
	val bytes = Base64.decode(this, Base64.URL_SAFE or Base64.NO_WRAP)
	require(bytes.size == 6) { "Comick HID must decode to 6 bytes: $this" }
	return bytes.fold(0L) { acc, byte ->
		(acc shl 8) or (byte.toLong() and 0xFF)
	}
}

internal fun Long.toHid(): String {
	require(this in 0 until (1L shl 48)) { "Comick ID is outside the 48-bit HID range: $this" }
	val bytes = ByteArray(6) { index ->
		(this shr (8 * (5 - index))).toByte()
	}
	return Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)
}

internal fun JSONObject.toComickStatus(): Int = when (optInt("status", -1)) {
	1 -> 1 // Reading
	2 -> 2 // Completed
	3 -> 3 // On hold
	4 -> 4 // Dropped
	5 -> 5 // Plan to read
	else -> throw IllegalArgumentException("Unknown Comick reading status: ${opt("status")}")
}

internal fun comickStatus(status: String?): Int? = when (status?.toIntOrNull()) {
	1, 2, 3, 4, 5 -> status?.toInt()
	else -> null
}
