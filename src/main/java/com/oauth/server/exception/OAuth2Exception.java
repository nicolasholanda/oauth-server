package com.oauth.server.exception;

public class OAuth2Exception extends RuntimeException {

    private final OAuth2ErrorCode errorCode;
    private final String errorDescription;

    public OAuth2Exception(OAuth2ErrorCode errorCode, String errorDescription) {
        super(errorCode.getValue() + (errorDescription != null ? ": " + errorDescription : ""));
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
    }

    public OAuth2ErrorCode getErrorCode() {
        return errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }
}
