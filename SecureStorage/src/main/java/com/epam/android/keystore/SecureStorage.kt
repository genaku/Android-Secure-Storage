package com.epam.android.keystore

import android.content.Context
import java.security.KeyStoreException

class SecureStorage(context: Context) {

    private var versionStrategy: SensitiveInfoModule? = null

    init {
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            setStrategy(SafeStorageM(context))
        } else
            setStrategy(SafeStoragePreM(context))
    }

    fun setStrategy(strategy: SensitiveInfoModule) {
        this.versionStrategy = strategy
    }

    @Throws(SecureStorageException::class)
    operator fun set(key: String, value: String) {
        versionStrategy?.save(key, value)
    }

    @Throws(SecureStorageException::class)
    operator fun get(key: String?): String? {
        return versionStrategy?.get(key)
    }

    fun clear(key: String) {
        versionStrategy?.clear(key)
    }

    @Throws(KeyStoreException::class)
    fun erase() {
        versionStrategy?.erase()
    }

    companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val KEY_ALIAS = "aliaskeystore"
    }
}
