package com.epam.android.keystore

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.support.annotation.RequiresApi
import android.util.Base64
import com.epam.android.keystore.SecureStorage.Companion.ANDROID_KEY_STORE
import java.io.IOException
import java.security.*
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec

@RequiresApi(api = Build.VERSION_CODES.M)
class SecureStorageM(context: Context, private val keyAlias: String) : ISecureStorage {

    private var secretKey: SecretKey = initSecretKey(keyAlias)
    private var cipher: Cipher = Cipher.getInstance(CIPHER_TYPE)
    private var preferences: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)
    private lateinit var keyStore: KeyStore

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
        keyStore.deleteEntry(keyAlias)
    }

    @Throws(SecureStorageException::class)
    override fun set(key: String, value: String) {
        try {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            putPref(I_VECTOR + key, Arrays.toString(cipher.iv))
            val encryption = cipher.doFinal(value.toUtf8ByteArray())
            val encryptedBase64Encoded = Base64.encodeToString(encryption, Base64.DEFAULT)
            putPref(key, encryptedBase64Encoded)
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: IOException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: BadPaddingException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: IllegalBlockSizeException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        }
    }

    override fun clear(key: String) {
        preferences.edit().remove(key).apply()
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    @Throws(SecureStorageException::class)
    override fun get(key: String): String? {
        if (key.isEmpty()) {
            throw IllegalArgumentException("Key should not be empty")
        }

        if (!isSet(I_VECTOR + key) || !isSet(key)) {
            return null
        }

        try {
            val value = getPref(key)
            val iv = getByteArray(getPref(I_VECTOR + key))
            val ivParameterSpec = IvParameterSpec(iv)
            val secretKeyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.SecretKeyEntry?
                    ?: return null
            cipher.init(Cipher.DECRYPT_MODE, secretKeyEntry.secretKey, ivParameterSpec)
            return if (value.isNullOrEmpty()) null else String(cipher.doFinal(Base64.decode(value, Base64.DEFAULT)), UTF8_CHARSET)
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

    private fun putPref(key: String, value: String) =
            preferences.edit().putString(key, value).apply()


    companion object {
        private const val CIPHER_TYPE = "AES/CBC/PKCS7Padding"
        private const val I_VECTOR = "valueV"
    }
}
