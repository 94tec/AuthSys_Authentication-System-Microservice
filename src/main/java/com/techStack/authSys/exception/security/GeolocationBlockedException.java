package com.techStack.authSys.exception.security;

import com.techStack.authSys.exception.service.CustomException;
import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Geolocation blocked exception
 */
@Getter
public class GeolocationBlockedException extends CustomException {
    private final String country;

    public GeolocationBlockedException(String country) {
        super(HttpStatus.FORBIDDEN,
                "Registration not available from this location");
        this.country = country;
    }

}
