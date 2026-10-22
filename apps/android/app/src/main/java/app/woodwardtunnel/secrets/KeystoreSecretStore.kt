package app.woodwardtunnel.secrets

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import uniffi.wtcore.SecretCallbacks
import java.io.File
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Secret store for the Rust core. Values are encrypted with an AES-256-GCM key that lives in the
 * Android Keystore (never exported); only ciphertext is written to app-private storage.
 *
 * File format: 1 version byte, 12 byte IV, ciphertext+tag. The secret id is bound in as
 * additional authenticated data so a ciphertext cannot be swapped between ids.
 * Nothing in here logs ids or values.
 */
class KeystoreSecretStore(private val dir: File) : SecretCallbacks {

    private val lock = Any()

    init {
        dir.mkdirs()
    }

    override fun put(id: String, value: String): Boolean = synchronized(lock) {
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, key())
            cipher.updateAAD(id.toByteArray(Charsets.UTF_8))
            val ct = cipher.doFinal(value.toByteArray(Charsets.UTF_8))
            val iv = cipher.iv
            val out = ByteArray(1 + iv.size + ct.size)
            out[0] = VERSION
            System.arraycopy(iv, 0, out, 1, iv.size)
            System.arraycopy(ct, 0, out, 1 + iv.size, ct.size)
            val target = fileFor(id)
            val tmp = File(dir, target.name + ".tmp")
            tmp.writeBytes(Base64.encode(out, Base64.NO_WRAP))
            if (!tmp.renameTo(target)) {
                tmp.delete()
                return false
            }
            true
        } catch (e: Exception) {
            Log.w(TAG, "secret write failed")
            false
        }
    }

    override fun get(id: String): String? = synchronized(lock) {
        val f = fileFor(id)
        if (!f.isFile) return null
        try {
            val raw = Base64.decode(f.readBytes(), Base64.NO_WRAP)
            if (raw.size < 1 + IV_BYTES + 16 || raw[0] != VERSION) return null
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(TAG_BITS, raw, 1, IV_BYTES))
            cipher.updateAAD(id.toByteArray(Charsets.UTF_8))
            String(cipher.doFinal(raw, 1 + IV_BYTES, raw.size - 1 - IV_BYTES), Charsets.UTF_8)
        } catch (e: Exception) {
            Log.w(TAG, "secret read failed")
            null
        }
    }

    override fun delete(id: String): Boolean = synchronized(lock) {
        val f = fileFor(id)
        !f.exists() || f.delete()
    }

    private fun fileFor(id: String): File {
        val digest = MessageDigest.getInstance("SHA-256").digest(id.toByteArray(Charsets.UTF_8))
        return File(dir, digest.joinToString("") { "%02x".format(it) })
    }

    private fun key(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return gen.generateKey()
    }

    private companion object {
        const val TAG = "WtSecrets"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val ALIAS = "wt_secret_key_v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val VERSION: Byte = 1
        const val IV_BYTES = 12
        const val TAG_BITS = 128
    }
}
