package com.epam.android.keystore

import android.content.Context
import android.content.SharedPreferences
import android.preference.PreferenceManager
import android.util.Base64
import com.cossacklabs.themis.SecureCell
import com.cossacklabs.themis.SecureCell.MODE_SEAL
import com.cossacklabs.themis.SecureCellData

class ThemisSecureStorage(context: Context, private val suffix: String = "") : ISecureStorage {

    private var preferences: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)

    override fun set(key: String, value: String) {
        require(key.isNotBlank()) { "Key should not be empty" }

        val storeKey = prepareKey(key)

        val sc = SecureCell(storeKey.toUtf8ByteArray(), MODE_SEAL)
        val protectedData = sc.protect(storeKey.toUtf8ByteArray(), prepareValue(value).toUtf8ByteArray())
        val encodedString = Base64.encodeToString(protectedData.protectedData, Base64.NO_WRAP)

        this.preferences.edit().putString(storeKey, encodedString).apply()
    }

    override fun clear(key: String) {
        preferences.edit().remove(prepareKey(key)).apply()
    }

    @Throws(SecureStorageException::class)
    override fun erase() {
        throw SecureStorageException("Not realised")
    }

    override fun get(key: String): String? {
        require(key.isNotBlank()) { "Key should not be empty" }

        val storeKey = prepareKey(key)

        val encodedString = preferences.getString(storeKey, null) ?: return null

        val decodedString = Base64.decode(encodedString, Base64.NO_WRAP)
        val encryptedData = SecureCellData(decodedString, null)

        val sc = SecureCell(storeKey.toUtf8ByteArray(), MODE_SEAL)
        val unprotectedData = sc.unprotect(storeKey.toUtf8ByteArray(), encryptedData)

        return sanitizeValue(String(unprotectedData, UTF8_CHARSET))
    }

    private fun prepareKey(key: String): String =
            key.trim()

    private fun prepareValue(value: String): String =
            value + suffix

    private fun sanitizeValue(value: String): String =
            value.removeSuffix(suffix)
}