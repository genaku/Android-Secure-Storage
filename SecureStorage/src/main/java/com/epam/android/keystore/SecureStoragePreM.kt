@file:Suppress("DEPRECATION")

package com.epam.android.keystore


import android.annotation.TargetApi
import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.preference.PreferenceManager
import android.security.KeyPairGeneratorSpec
import android.util.Base64
import com.epam.android.keystore.SecureStorage.Companion.ANDROID_KEY_STORE
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.math.BigInteger
import java.security.*
import java.security.cert.CertificateException
import java.util.*
import javax.crypto.Cipher
import javax.crypto.CipherInputStream
import javax.crypto.CipherOutputStream
import javax.crypto.NoSuchPaddingException
import javax.security.auth.x500.X500Principal

class SecureStoragePreM @Throws(InvalidAlgorithmParameterException::class, KeyStoreException::class, CertificateException::class, NoSuchAlgorithmException::class, IOException::class, NoSuchProviderException::class)
constructor(context: Context, val keyAlias: String) : ISecureStorage {

    private lateinit var keyStore: KeyStore

    private val preferences: SharedPreferences = PreferenceManager.getDefaultSharedPreferences(context)

    init {
        initKeyStore(context)
    }

    @TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Throws(KeyStoreException::class, IOException::class, NoSuchAlgorithmException::class, CertificateException::class, NoSuchProviderException::class, InvalidAlgorithmParameterException::class)
    private fun initKeyStore(context: Context) {
        keyStore = KeyStore.getInstance(ANDROID_KEY_STORE)
        keyStore.load(null)
        // Generate the RSA key pairs
        if (!keyStore.containsAlias(keyAlias)) {
            // Generate a key pair for encryption
            val start = Calendar.getInstance()
            val end = Calendar.getInstance()
            end.add(Calendar.YEAR, 1)
            val spec = KeyPairGeneratorSpec.Builder(context)
                    .setAlias(keyAlias)
                    .setSubject(X500Principal("CN=$keyAlias, O=Android Authority , C=COMPANY"))
                    .setSerialNumber(BigInteger.TEN)
                    .setStartDate(start.time)
                    .setEndDate(end.time)
                    .build()
            val kpg = KeyPairGenerator.getInstance("RSA", ANDROID_KEY_STORE)
            kpg.initialize(spec)
            kpg.generateKeyPair()
        }
    }

    @Throws(SecureStorageException::class)
    override fun set(key: String, value: String) {
        try {
            val privateKeyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry
            // Encrypt the text
            val inputCipher = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER)
            inputCipher.init(Cipher.ENCRYPT_MODE, privateKeyEntry.certificate.publicKey)

            val outputStream = ByteArrayOutputStream()
            val cipherOutputStream = CipherOutputStream(outputStream, inputCipher)
            cipherOutputStream.write(value.toUtf8ByteArray())
            cipherOutputStream.close()

            val cryptoText = outputStream.toByteArray()
            val encryptedString = Base64.encodeToString(cryptoText, Base64.DEFAULT)
            putPref(key, encryptedString)
            outputStream.close()
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage: No such algorithm $CIPHER_TYPE")
        } catch (e: KeyStoreException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: IOException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: UnrecoverableEntryException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        } catch (e: NoSuchProviderException) {
            e.printStackTrace()
            throw SecureStorageException("Error sa ve or cypher value to the storage")
        }
    }

    private fun putPref(key: String, value: String) {
        preferences.edit().putString(key, value).apply()
    }

    override fun clear(key: String) {
        preferences.edit().remove(key).apply()
    }

    @Throws(KeyStoreException::class)
    override fun erase() {
        keyStore.deleteEntry(keyAlias)
    }

    private fun getPref(key: String): String =
            preferences.getString(key, "")!!

    @Throws(SecureStorageException::class)
    override fun get(key: String): String? {
        if (key.isEmpty()) {
            throw IllegalArgumentException("Key should not be empty")
        }

        val privateKeyEntry: KeyStore.PrivateKeyEntry?
        try {
            privateKeyEntry = keyStore.getEntry(keyAlias, null) as KeyStore.PrivateKeyEntry? ?: return null

            val cipher = Cipher.getInstance(CIPHER_TYPE, CIPHER_PROVIDER)
            cipher.init(Cipher.DECRYPT_MODE, privateKeyEntry.privateKey)

            val value = getPref(key)
            if (value.isEmpty()) return null
            val bytes = getBytes(cipher, value)
            return String(bytes, UTF8_CHARSET)
        } catch (e: NoSuchAlgorithmException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage: No such algorithm $CIPHER_TYPE")
        } catch (e: KeyStoreException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: InvalidKeyException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: IOException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: NoSuchPaddingException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: UnrecoverableEntryException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        } catch (e: NoSuchProviderException) {
            e.printStackTrace()
            throw SecureStorageException("Error get value from the storage")
        }
    }

    @Throws(IOException::class)
    private fun getBytes(cipher: Cipher, value: String): ByteArray {
        val cipherInputStream = CipherInputStream(
                ByteArrayInputStream(Base64.decode(value, Base64.DEFAULT)), cipher)
        val values = ArrayList<Byte>()
        var nextByte = cipherInputStream.read()

        while (nextByte != -1) {
            values.add(nextByte.toByte())
            nextByte = cipherInputStream.read()
        }

        val bytes = ByteArray(values.size)
        for (i in bytes.indices) {
            bytes[i] = values[i]
        }
        return bytes
    }

    companion object {
        private const val CIPHER_TYPE = "RSA/ECB/PKCS1Padding"
        private const val CIPHER_PROVIDER = "AndroidOpenSSL"
    }
}
