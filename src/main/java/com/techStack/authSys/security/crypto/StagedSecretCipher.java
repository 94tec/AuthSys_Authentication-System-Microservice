package com.techStack.authSys.security.crypto;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AES-256-GCM encryption for short-lived secrets staged in Redis
 * (e.g. the first-time-login password).
 *
 * Output format: base64( iv[12] || ciphertext+tag )
 *
 * The "context" string (use the userId) is authenticated as AAD, so a ciphertext
 * copied to another user's key fails to decrypt.
 *
 * Key: 32 random bytes, base64-encoded, supplied via environment variable.
 *   Generate with:  openssl rand -base64 32
 */
@Component
public class StagedSecretCipher {

    private static final String ALGORITHM = "AES/GCM/NoPadding";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public StagedSecretCipher(@Value("${encryption.secret-key}") String base64Key) {
        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(base64Key.trim());
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("security.staging.encryption-key must be valid base64", e);
        }
        if (raw.length != 32) {
            throw new IllegalStateException(
                    "security.staging.encryption-key must decode to 32 bytes (AES-256), got " + raw.length);
        }
        this.key = new SecretKeySpec(raw, "AES");
    }

    public String encrypt(String plaintext, String context) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(
                    ByteBuffer.allocate(iv.length + ciphertext.length).put(iv).put(ciphertext).array());
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public String decrypt(String token, String context) {
        try {
            byte[] all = Base64.getDecoder().decode(token);
            if (all.length <= IV_BYTES) {
                throw new IllegalArgumentException("Ciphertext too short");
            }

            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, all, 0, IV_BYTES));
            cipher.updateAAD(context.getBytes(StandardCharsets.UTF_8));
            byte[] plain = cipher.doFinal(all, IV_BYTES, all.length - IV_BYTES);

            return new String(plain, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            // never include the token or plaintext in the message
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}