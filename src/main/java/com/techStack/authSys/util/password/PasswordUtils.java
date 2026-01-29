package com.techStack.authSys.util.password;

import java.security.SecureRandom;

public class PasswordUtils {

    // SecureRandom instance for better randomness
    private static final SecureRandom random = new SecureRandom();
    private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String DIGITS = "0123456789";
    private static final String SPECIAL_CHARACTERS = "!@#$%^&*()-_=+[]{}|;:,.<>?/";

    private static final String ALL_CHARACTERS = LOWERCASE + UPPERCASE + DIGITS + SPECIAL_CHARACTERS;

    public static String generateSecurePassword(int length) {
        StringBuilder password = new StringBuilder(length);

        // Ensure password contains at least one character of each type (uppercase, lowercase, digit, special character)
        password.append(getRandomCharacter(LOWERCASE));
        password.append(getRandomCharacter(UPPERCASE));
        password.append(getRandomCharacter(DIGITS));
        password.append(getRandomCharacter(SPECIAL_CHARACTERS));

        // Fill the remaining password length with random characters
        for (int i = 4; i < length; i++) {
            password.append(getRandomCharacter(ALL_CHARACTERS));
        }

        // Shuffle to avoid predictable patterns
        return shuffleString(password.toString());
    }

    private static char getRandomCharacter(String source) {
        return source.charAt(random.nextInt(source.length()));
    }

    private static String shuffleString(String input) {
        char[] characters = input.toCharArray();
        for (int i = characters.length - 1; i > 0; i--) {
            int j = random.nextInt(i + 1);
            char temp = characters[i];
            characters[i] = characters[j];
            characters[j] = temp;
        }
        return new String(characters);
    }
}

