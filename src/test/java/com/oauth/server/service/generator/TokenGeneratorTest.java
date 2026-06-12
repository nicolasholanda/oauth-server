package com.oauth.server.service.generator;

import com.oauth.server.config.JwtProperties;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.User;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class TokenGeneratorTest {

    private static final String SECRET = "test-secret-test-secret-test-secret-test-secret-test-secret-1234";

    private JwtProperties jwtProperties;
    private TokenGenerator tokenGenerator;
    private SecretKey verifyKey;

    @BeforeEach
    void setUp() {
        jwtProperties = new JwtProperties();
        jwtProperties.setIssuer("http://localhost:8080");
        jwtProperties.setSecret(SECRET);
        jwtProperties.setAccessTokenTtlSeconds(3600);
        tokenGenerator = new TokenGenerator(jwtProperties);
        verifyKey = Keys.hmacShaKeyFor(SECRET.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void generatesJwtWithUserSubjectAndExpectedClaims() {
        Client client = newClient("demo-client");
        User user = newUser("alice");
        Instant expiresAt = Instant.now().plusSeconds(600);

        String token = tokenGenerator.generate(client, user, Set.of("read", "write"), expiresAt);

        Claims claims = parse(token);
        assertThat(claims.getSubject()).isEqualTo("alice");
        assertThat(claims.getIssuer()).isEqualTo("http://localhost:8080");
        assertThat(claims.getAudience()).contains("demo-client");
        assertThat(claims.get("client_id", String.class)).isEqualTo("demo-client");
        assertThat(claims.get("token_type", String.class)).isEqualTo("access_token");
        assertThat(claims.get("scope", String.class)).contains("read").contains("write");
        assertThat(claims.getExpiration().toInstant().getEpochSecond())
                .isEqualTo(expiresAt.getEpochSecond());
    }

    @Test
    void usesClientIdAsSubjectWhenUserIsNull() {
        Client client = newClient("svc-client");
        Instant expiresAt = Instant.now().plusSeconds(60);

        String token = tokenGenerator.generate(client, null, Set.of("read"), expiresAt);

        Claims claims = parse(token);
        assertThat(claims.getSubject()).isEqualTo("svc-client");
    }

    @Test
    void emitsUniqueTokenIdsAcrossInvocations() {
        Client client = newClient("demo-client");
        Instant expiresAt = Instant.now().plusSeconds(60);

        String first = tokenGenerator.generate(client, null, Set.of("read"), expiresAt);
        String second = tokenGenerator.generate(client, null, Set.of("read"), expiresAt);

        assertThat(parse(first).getId()).isNotEqualTo(parse(second).getId());
    }

    private Claims parse(String token) {
        return Jwts.parser()
                .verifyWith(verifyKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private Client newClient(String id) {
        Client client = new Client();
        client.setClientId(id);
        return client;
    }

    private User newUser(String username) {
        User user = new User();
        user.setUsername(username);
        return user;
    }
}
