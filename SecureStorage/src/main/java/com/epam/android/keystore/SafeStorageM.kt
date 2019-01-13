package com.epam.android.keystore

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.util.Base64

import java.io.IOException
import java.nio.charset.StandardCharsets
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.KeyStore
import java.security.KeyStoreException
import java.security.NoSuchAlgorithmException
import java.security.UnrecoverableEntryException
import java.util.Arrays

import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.IllegalBlockSizeException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

import com.epam.android.keystore.SecureStorage.Companion.ANDROID_KEY_STORE
import com.epam.android.keystore.SecureStorage.Companion.KEY_ALIAS

class SafeStorageM : SensitiveInfoModule {

    private var secretKey: SecretKey
    private var cipher: Cipher
    private var preferences: SharedPreferences
    private lateinit var keyStore: KeyStore

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(Exception::class)
    constructor(context: Context) {
        cipher = Cipher.getInstance(AESGCMNOPADDING)
        secretKey = initSecretKey(KEY_ALIAS)
        preferences = PreferenceManager.getDefaultSharedPreferences(context)
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(Exception::class)
    constructor(preferences: SharedPreferences) {
        cipher = Cipher.getInstance(AESGCMNOPADDING)
        secretKey = initSecretKey(KEY_ALIAS)
        this.preferences = preferences
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(Exception::class)
    private fun generatorKey(alias: String): SecretKey {
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build()
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE)
        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(Exception::class)
    private fun initSecretKey(alias: String): SecretKey {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        return if (keyStore.containsAlias(alias)) {
            val secretKeyEntry = keyStore.getEntry(alias, null) as KeyStore.SecretKeyEntry
            secretKeyEntry.secretKey
        } else {
            generatorKey(alias)
        }
    }

    @Throws(KeyStoreException::class)
    override fun erase() {
        keyStore.deleteEntry(KEY_ALIAS)
    }

    @Throws(SecureStorageException::class)
    override fun save(key: String, value: String) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            putPref(I_VECTOR + key, Arrays.toString(cipher.iv))
            val encryption = cipher.doFinal(value.toByteArray(charset("UTF-8")))
            val encryptedBase64Encoded = Base64.encodeToString(encryption, Base64.DEFAULT)
            putPref(key, encryptedBase64Encoded)
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
            throw SecureStorageException("Error save or cypher value to the storage")
        } catch (e: IOException) {
            e.printStackTrace()
            throw SecureStorageException("Error save or cypher value to the storage")
        } catch (e: BadPaddingException) {
            e.printStackTrace()
            throw SecureStorageException("Error save or cypher value to the storage")
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
            throw SecureStorageException("Error save or cypher value to the storage")
        }
    }

    override fun clear(key: String) {
        preferences.edit().remove(key).apply()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(SecureStorageException::class)
    override fun get(key: String?): String? {
        if (key.isNullOrEmpty()) {
            throw IllegalArgumentException("Key should not be null or empty")
        }

        if (!isSet(I_VECTOR + key) || !isSet(key)) {
            return null
        }

        try {
            val value = getPref(key)
            val iv = getByteArray(getPref(I_VECTOR + key))
            val ivParameterSpec = IvParameterSpec(iv)
            val secretKeyEntry = keyStore.getEntry(KEY_ALIAS, null) as KeyStore.SecretKeyEntry?
                    ?: return null
            cipher.init(Cipher.DECRYPT_MODE, secretKeyEntry.secretKey, ivParameterSpec)
            return if (value.isNullOrEmpty()) null else String(cipher.doFinal(Base64.decode(value, Base64.DEFAULT)), StandardCharsets.UTF_8)
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: BadPaddingException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: InvalidAlgorithmParameterException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: UnrecoverableEntryException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: KeyStoreException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        }

    }

    private fun getByteArray(stringArray: String?): ByteArray? {
        stringArray ?: return null
        val split = stringArray.substring(1, stringArray.length - 1).split(", ".toRegex()).dropLastWhile { it.isEmpty() }.toTypedArray()
        val array = ByteArray(split.size)
        for (i in split.indices) {
            array[i] = java.lang.Byte.parseByte(split[i])
        }
        return array
    }

    private fun isSet(key: String): Boolean =
            preferences.contains(key)

    private fun getPref(key: String): String? =
            preferences.getString(key, "")

    private fun putPref(key: String, value: String) {
        preferences.edit().putString(key, value).apply()
    }

    companion object {
        private const val AESGCMNOPADDING = "AES/CBC/PKCS7Padding"
        private const val I_VECTOR = "valueV"
    }
}
