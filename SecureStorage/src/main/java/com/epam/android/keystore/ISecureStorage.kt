package com.epam.android.keystore

import java.security.KeyStoreException

interface ISecureStorage {

    @Throws(SecureStorageException::class)
    fun set(key: String, value: String)

    fun clear(key: String)

    @Throws(KeyStoreException::class)
    fun erase()

    @Throws(SecureStorageException::class)
    operator fun get(key: String): String?
}