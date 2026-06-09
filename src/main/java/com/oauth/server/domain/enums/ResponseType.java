package com.oauth.server.domain.enums;

import java.util.Arrays;
import java.util.Optional;

public enum ResponseType {

    CODE("code"),
    TOKEN("token");

    private final String value;

    ResponseType(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }

    public static Optional<ResponseType> fromValue(String value) {
        return Arrays.stream(values())
                .filter(r -> r.value.equalsIgnoreCase(value))
                .findFirst();
    }
}
