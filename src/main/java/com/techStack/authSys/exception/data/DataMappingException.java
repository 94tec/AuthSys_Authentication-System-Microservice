package com.techStack.authSys.exception.data;

import com.techStack.authSys.exception.service.CustomException;
import org.springframework.http.HttpStatus;

public class DataMappingException extends CustomException {
    public DataMappingException(String message) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message);
    }

    public DataMappingException(String message, Throwable cause) {
        super(HttpStatus.INTERNAL_SERVER_ERROR, message, cause);
    }
}