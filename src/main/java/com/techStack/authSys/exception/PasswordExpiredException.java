package com.techStack.authSys.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public class PasswordExpiredException extends CustomException {

    private final String daysExpired; // 💡 Field to store how many days ago it expired
    /**
     * Constructor for a password expiration exception.
     * Sets HTTP status to 403 (FORBIDDEN).
     *
     * @param daysExpired The number of days the password has been expired for.
     */
    public PasswordExpiredException(String daysExpired) {
        super(
                HttpStatus.FORBIDDEN,
                String.format("Password has expired. It is %d days past the required reset date.", daysExpired)
        );
        this.daysExpired = daysExpired;
    }

}

