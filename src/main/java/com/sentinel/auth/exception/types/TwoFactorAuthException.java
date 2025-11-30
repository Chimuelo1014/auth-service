package com.sentinel.auth.exception.types;

public class TwoFactorAuthException extends RuntimeException {
    public TwoFactorAuthException(String message) {
        super(message);
    }
}