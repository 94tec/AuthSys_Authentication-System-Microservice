package com.techStack.authSys.exception;

public class TransientAuthenticationException extends RuntimeException
{     public TransientAuthenticationException(String message) {
        super(message);
      }
    public TransientAuthenticationException(String message, Throwable cause) {
        super(message, cause);

    }

}
