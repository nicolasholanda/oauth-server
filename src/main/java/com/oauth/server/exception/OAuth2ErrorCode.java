package com.oauth.server.exception;

import org.springframework.http.HttpStatus;

public enum OAuth2ErrorCode {

    INVALID_REQUEST("invalid_request", HttpStatus.BAD_REQUEST),
    INVALID_CLIENT("invalid_client", HttpStatus.UNAUTHORIZED),
    INVALID_GRANT("invalid_grant", HttpStatus.BAD_REQUEST),
    UNAUTHORIZED_CLIENT("unauthorized_client", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_GRANT_TYPE("unsupported_grant_type", HttpStatus.BAD_REQUEST),
    UNSUPPORTED_RESPONSE_TYPE("unsupported_response_type", HttpStatus.BAD_REQUEST),
    INVALID_SCOPE("invalid_scope", HttpStatus.BAD_REQUEST),
    ACCESS_DENIED("access_denied", HttpStatus.FORBIDDEN),
    SERVER_ERROR("server_error", HttpStatus.INTERNAL_SERVER_ERROR),
    TEMPORARILY_UNAVAILABLE("temporarily_unavailable", HttpStatus.SERVICE_UNAVAILABLE);

    private final String value;
    private final HttpStatus httpStatus;

    OAuth2ErrorCode(String value, HttpStatus httpStatus) {
        this.value = value;
        this.httpStatus = httpStatus;
    }

    public String getValue() {
        return value;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
