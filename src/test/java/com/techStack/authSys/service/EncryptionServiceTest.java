package com.techStack.authSys.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Base64;

import static org.assertj.core.api.Assertions.*;

class EncryptionServiceTest {

    private EncryptionService encryptionService;
    private String base64Key;

    @BeforeEach
    void setUp() throws Exception {
        encryptionService = new EncryptionService();
        // Generate a proper AES key for testing
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128); // 128-bit for testing
        SecretKey secretKey = keyGen.generateKey();
        base64Key = Base64.getEncoder().encodeToString(secretKey.getEncoded());
        encryptionService.setSecretKeyBase64(base64Key);
        encryptionService.init();
    }

    @Test
    void testEncryptDecrypt() {
        String data = "sensitiveData123";
        String encrypted = encryptionService.encrypt(data);

        assertThat(encrypted).isNotBlank()
                .isNotEqualTo(data)
                .containsPattern("^[A-Za-z0-9+/]+={0,2}$"); // Base64 pattern

        String decrypted = encryptionService.decrypt(encrypted);
        assertThat(decrypted).isEqualTo(data);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "   "})
    void testEncryptShouldFailForInvalidInput(String input) {
        assertThatThrownBy(() -> encryptionService.encrypt(input))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("cannot be null or empty");
    }

    @Test
    void testDecryptShouldFailForInvalidData() {
        assertThatThrownBy(() -> encryptionService.decrypt("invalid-base64"))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Decryption failed");
    }

    @Test
    void testDecryptShouldFailForTamperedData() {
        String data = "sensitiveData123";
        String encrypted = encryptionService.encrypt(data);
        String tampered = encrypted.substring(0, encrypted.length() - 4) + "abcd";

        assertThatThrownBy(() -> encryptionService.decrypt(tampered))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Decryption failed");
    }

    @Test
    void testHashToken() {
        String token = "secureToken123";
        String hash = encryptionService.hashToken(token);

        assertThat(hash).isNotBlank()
                .hasSizeGreaterThan(20)
                .containsPattern("^[A-Za-z0-9+/]+={0,2}$"); // Base64 pattern

        // Verify same input produces same hash
        String hash2 = encryptionService.hashToken(token);
        assertThat(hash2).isEqualTo(hash);
    }

    @Test
    void testDifferentTokensProduceDifferentHashes() {
        String token1 = "token1";
        String token2 = "token2";

        assertThat(encryptionService.hashToken(token1))
                .isNotEqualTo(encryptionService.hashToken(token2));
    }
}