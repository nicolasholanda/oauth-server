package com.oauth.server.service.generator;

import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.util.Base64;

@Component
public class CodeGenerator {

    private static final int DEFAULT_BYTE_LENGTH = 32;

    private final SecureRandom secureRandom = new SecureRandom();
    private final Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();

    public String generate() {
        return generate(DEFAULT_BYTE_LENGTH);
    }

    public String generate(int byteLength) {
        byte[] bytes = new byte[byteLength];
        secureRandom.nextBytes(bytes);
        return encoder.encodeToString(bytes);
    }
}
