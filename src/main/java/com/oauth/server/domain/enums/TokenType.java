package com.oauth.server.domain.enums;

public enum TokenType {

    BEARER("Bearer");

    private final String value;

    TokenType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
