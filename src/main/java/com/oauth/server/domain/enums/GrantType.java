package com.oauth.server.domain.enums;

import java.util.Arrays;
import java.util.Optional;

public enum GrantType {

    AUTHORIZATION_CODE("authorization_code"),
    CLIENT_CREDENTIALS("client_credentials"),
    PASSWORD("password"),
    REFRESH_TOKEN("refresh_token");

    private final String value;

    GrantType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Optional<GrantType> fromValue(String value) {
        return Arrays.stream(values())
                .filter(g -> g.value.equalsIgnoreCase(value))
                .findFirst();
    }
}
