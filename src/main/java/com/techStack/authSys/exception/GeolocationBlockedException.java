package com.techStack.authSys.exception;

import org.springframework.http.HttpStatus;

/**
 * Geolocation blocked exception
 */
public class GeolocationBlockedException extends CustomException {
    private final String country;

    public GeolocationBlockedException(String country) {
        super(HttpStatus.FORBIDDEN,
                "Registration not available from this location");
        this.country = country;
    }

    public String getCountry() {
        return country;
    }
}
