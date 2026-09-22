package com.syntecxhub.encryptedchat

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.ListView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import java.security.KeyStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Project 2 - Encrypted Android Chat (prototype)
 *
 * - AES-256-GCM encryption of every message.
 * - Key lives in the Android Keystore (hardware-backed on most devices),
 *   so the raw key material never exists in app memory or on disk -
 *   this is the "secure storage" requirement from the task.
 * - Since this is a single-device prototype (no server yet), "sending"
 *   encrypts the message, and "receiving" simulates an incoming reply
 *   by decrypting it right back - showing the full encrypt -> transmit ->
 *   decrypt pipeline that a real client/server version would use.
 */
class MainActivity : AppCompatActivity() {

    private val keyAlias = "chat_aes_key"
    private val androidKeyStore = "AndroidKeyStore"
    private val history = mutableListOf<String>()
    private lateinit var adapter: ArrayAdapter<String>

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        val messageInput = findViewById<EditText>(R.id.messageInput)
        val sendButton = findViewById<Button>(R.id.sendButton)
        val messageList = findViewById<ListView>(R.id.messageList)

        adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1, history)
        messageList.adapter = adapter

        // Make sure a key exists in the Keystore before we need it.
        try {
            getOrCreateKey()
        } catch (e: Exception) {
            toast("Key setup failed: ${e.message}")
        }

        sendButton.setOnClickListener {
            val text = messageInput.text.toString().trim()
            if (text.isEmpty()) {
                toast("Type a message first")
                return@setOnClickListener
            }
            sendMessage(text)
            messageInput.text.clear()
        }
    }

    /** Handles the full local send flow with error handling. */
    private fun sendMessage(plaintext: String) {
        try {
            val encrypted = encrypt(plaintext)
            addToHistory("You (sent, encrypted): ${encrypted.take(40)}...")

            // Simulate the message travelling to a server/peer and coming
            // back - a real app would swap this block for actual network
            // I/O (sockets/HTTP) using the same encrypt()/decrypt() calls.
            Handler(Looper.getMainLooper()).postDelayed({
                try {
                    val decrypted = decrypt(encrypted)
                    addToHistory("Peer (received, decrypted): $decrypted")
                } catch (e: Exception) {
                    addToHistory("[Error decrypting incoming message: ${e.message}]")
                }
            }, 500)

        } catch (e: Exception) {
            toast("Encryption failed: ${e.message}")
        }
    }

    private fun addToHistory(line: String) {
        val timestamp = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        history.add("[$timestamp] $line")
        adapter.notifyDataSetChanged()
    }

    // ---------- AES-256-GCM encryption using an Android Keystore key ----------

    private fun getOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(androidKeyStore)
        keyStore.load(null)

        val existing = keyStore.getKey(keyAlias, null) as? SecretKey
        if (existing != null) return existing

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES, androidKeyStore
        )
        val spec = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    /** Encrypts plaintext, returns Base64(iv + ciphertext) so it's easy to
     * store or "transmit" as a single string. */
    private fun encrypt(plaintext: String): String {
        val key = getOrCreateKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv // fresh random IV generated per call - safe usage
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = iv + ciphertext
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    private fun decrypt(base64Combined: String): String {
        val key = getOrCreateKey()
        val combined = Base64.decode(base64Combined, Base64.NO_WRAP)
        val iv = combined.copyOfRange(0, 12) // GCM IV is 12 bytes
        val ciphertext = combined.copyOfRange(12, combined.size)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val spec = GCMParameterSpec(128, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        val plainBytes = cipher.doFinal(ciphertext)
        return String(plainBytes, Charsets.UTF_8)
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }
}
