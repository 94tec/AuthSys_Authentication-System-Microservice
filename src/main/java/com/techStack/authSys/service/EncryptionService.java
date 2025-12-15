package com.techStack.authSys.service;

import lombok.Getter;
import lombok.Setter;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

@Service
public class EncryptionService {

    private static final Logger logger = LoggerFactory.getLogger(EncryptionService.class);

    // AES Configuration
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final int IV_LENGTH = 16;
    @Value("${encryption.secret-key}")
    @Getter @Setter private String secretKeyBase64;
    private SecretKeySpec secretKey;

    // Password Hashing Configuration
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int PBKDF2_ITERATIONS = 100000;
    private static final int PBKDF2_KEY_LENGTH = 256;
    private static final int PBKDF2_SALT_LENGTH = 16;
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/]+={0,2}$");
    private static final String SHA_256_ALGORITHM = "SHA-256";

    @PostConstruct
    public void init() {
        initAES();
    }

    private void initAES() {
        try {
            if (StringUtils.isBlank(secretKeyBase64)) {
                throw new IllegalStateException("Encryption key is not set. Ensure it's configured in properties.");
            }

            byte[] decodedKey = Base64.getDecoder().decode(secretKeyBase64);
            if (decodedKey.length != 16 && decodedKey.length != 24 && decodedKey.length != 32) {
                throw new IllegalStateException("Invalid AES key length. Must be 16, 24, or 32 bytes");
            }

            secretKey = new SecretKeySpec(decodedKey, "AES");
            logger.info("AES encryption initialized successfully");
        } catch (Exception e) {
            logger.error("AES initialization failed", e);
            throw new RuntimeException("Encryption service initialization failed", e);
        }
    }
    /**
     * Validates that the provided IP string is a properly formatted AES-encrypted value.
     * Ensures:
     * - Base64 format is valid
     * - Decoded content includes at least a full IV
     * - Decryption succeeds (optional strict mode)
     */
    public void validateEncryptedIp(String encryptedIp) {
        if (StringUtils.isBlank(encryptedIp)) {
            logger.warn("Encrypted IP validation failed: value is null or empty");
            throw new IllegalArgumentException("Encrypted IP cannot be null or empty");
        }

        // Step 1: Validate Base64 + length
        if (!isValidEncryptedFormat(encryptedIp)) {
            logger.warn("Encrypted IP validation failed: invalid Base64 or format [{}]", encryptedIp);
            throw new IllegalArgumentException("Invalid encrypted IP format");
        }

        // Step 2: Try decryption — determines structural AES validity
        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedIp);

            if (decoded.length < IV_LENGTH + 1) {
                logger.warn("Encrypted IP validation failed: decoded length too short. Length={}", decoded.length);
                throw new IllegalArgumentException("Invalid encrypted IP payload length");
            }

            // Attempt decryption — if it fails, the encrypted data is not valid
            String decrypted = decrypt(encryptedIp);

            // Optional: Validate decrypted IP format
            if (StringUtils.isBlank(decrypted)) {
                logger.warn("Decrypted IP is blank after successful AES decode");
                throw new IllegalArgumentException("Decrypted IP cannot be blank");
            }

            // Optional: Ensure it's a valid IPv4/IPv6 format
            if (!isValidIpFormat(decrypted)) {
                logger.warn("Decrypted IP failed IP format validation: {}", decrypted);
                throw new IllegalArgumentException("Decrypted IP is not a valid IP address");
            }

            logger.debug("Encrypted IP validated successfully");
        } catch (Exception e) {
            logger.error("Encrypted IP validation failed — AES decryption error: {}", e.getMessage());
            throw new IllegalArgumentException("Invalid encrypted IP", e);
        }
    }

    /**
     * Validates IPv4 or IPv6 format.
     */
    private boolean isValidIpFormat(String ip) {
        try {
            java.net.InetAddress.getByName(ip);
            return true;
        } catch (Exception ignored) {
            return false;
        }
    }

    // ==================== AES Encryption Methods ====================

    public String encrypt(String data) {
        if (StringUtils.isBlank(data)) {
            throw new IllegalArgumentException("Data to encrypt cannot be null or empty");
        }

        try {
            byte[] iv = new byte[IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encrypted = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

            byte[] combined = ByteBuffer.allocate(iv.length + encrypted.length)
                    .put(iv)
                    .put(encrypted)
                    .array();

            String encoded = Base64.getEncoder().encodeToString(combined);
            logger.debug("Data encrypted successfully (masked): {}***", data.substring(0, Math.min(3, data.length())));
            return encoded;
        } catch (Exception e) {
            logger.error("AES encryption failed", e);
            throw new RuntimeException("Encryption failed", e);
        }
    }

    public String decrypt(String encryptedData) {
        if (StringUtils.isBlank(encryptedData)) {
            throw new IllegalArgumentException("Data to decrypt cannot be null or empty");
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(encryptedData);
            ByteBuffer buffer = ByteBuffer.wrap(decoded);

            byte[] iv = new byte[IV_LENGTH];
            buffer.get(iv);
            byte[] encryptedBytes = new byte[buffer.remaining()];
            buffer.get(encryptedBytes);

            Cipher cipher = Cipher.getInstance(AES_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            byte[] decrypted = cipher.doFinal(encryptedBytes);
            String result = new String(decrypted, StandardCharsets.UTF_8);
            logger.debug("Data decrypted successfully.");
            return result;
            //return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.error("AES decryption failed", e);
            throw new RuntimeException("Decryption failed", e);
        }
    }

    public boolean isValidEncryptedFormat(String encryptedData) {
        if (StringUtils.isBlank(encryptedData)) return false;

        try {
            // Directly try decoding to catch any invalid Base64 issues
            byte[] decoded = Base64.getDecoder().decode(encryptedData);
            logger.debug("Decoded data length: {}", decoded.length);

            // Check that decoded length is acceptable (greater than or equal to IV length)
            if (decoded.length < IV_LENGTH) {
                logger.warn("Decoded data length is too short: {}", decoded.length);
                return false;
            }

            // If the Base64 pattern doesn't match, you could choose to throw an exception or log
            if (!BASE64_PATTERN.matcher(encryptedData).matches()) {
                logger.warn("Base64 format does not match the expected pattern: {}", encryptedData);
                return false;
            }

            return true;
        } catch (IllegalArgumentException e) {
            logger.warn("Invalid Base64 format: {}", encryptedData);
            return false;
        }
    }
    // ==================== Password Hashing Methods ====================

    public String hashPassword(String password) {
        if (StringUtils.isBlank(password)) {
            throw new IllegalArgumentException("Password cannot be null or empty");
        }

        try {
            SecureRandom random = new SecureRandom();
            byte[] salt = new byte[PBKDF2_SALT_LENGTH];
            random.nextBytes(salt);

            KeySpec spec = new PBEKeySpec(
                    password.toCharArray(),
                    salt,
                    PBKDF2_ITERATIONS,
                    PBKDF2_KEY_LENGTH
            );

            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] hash = factory.generateSecret(spec).getEncoded();

            return String.format(
                    "%d:%s:%s",
                    PBKDF2_ITERATIONS,
                    Base64.getEncoder().encodeToString(salt),
                    Base64.getEncoder().encodeToString(hash)
            );
        } catch (Exception e) {
            logger.error("Password hashing failed", e);
            throw new RuntimeException("Password hashing failed", e);
        }
    }

    public boolean matchesPassword(String plainTextPassword, String storedHash) {
        if (StringUtils.isBlank(plainTextPassword) || StringUtils.isBlank(storedHash)) {
            return false;
        }

        try {
            String[] parts = storedHash.split(":");
            if (parts.length != 3) {
                return false;
            }

            int iterations = Integer.parseInt(parts[0]);
            byte[] salt = Base64.getDecoder().decode(parts[1]);
            byte[] storedHashBytes = Base64.getDecoder().decode(parts[2]);

            KeySpec spec = new PBEKeySpec(
                    plainTextPassword.toCharArray(),
                    salt,
                    iterations,
                    storedHashBytes.length * 8
            );

            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] testHash = factory.generateSecret(spec).getEncoded();

            return MessageDigest.isEqual(storedHashBytes, testHash);
        } catch (Exception e) {
            logger.error("Password comparison failed", e);
            return false;
        }
    }

    // ==================== Migration Support ====================

    public boolean isLegacyEncrypted(String data) {
        return isValidEncryptedFormat(data) && !data.contains(":");
    }

    public String migratePassword(String plainText, String currentHash) {
        if (isLegacyEncrypted(currentHash)) {
            // Verify against old encryption
            if (matchesLegacy(plainText, currentHash)) {
                return hashPassword(plainText);
            }
            throw new IllegalArgumentException("Current password does not match");
        }
        throw new IllegalStateException("Password is not in legacy format");
    }

    private boolean matchesLegacy(String plainText, String encryptedText) {
        try {
            String decrypted = decrypt(encryptedText);
            return MessageDigest.isEqual(
                    plainText.getBytes(StandardCharsets.UTF_8),
                    decrypted.getBytes(StandardCharsets.UTF_8)
            );
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== Utility Methods ====================
    public String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance(SHA_256_ALGORITHM);
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            logger.error("SHA-256 algorithm not available", e);
            throw new RuntimeException("Error hashing token", e);
        }
    }
}
