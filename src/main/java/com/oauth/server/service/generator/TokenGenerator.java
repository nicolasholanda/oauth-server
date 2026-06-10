package com.oauth.server.service.generator;

import com.oauth.server.config.JwtProperties;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

@Component
public class TokenGenerator {

    private final JwtProperties jwtProperties;
    private final SecretKey signingKey;

    public TokenGenerator(JwtProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
        this.signingKey = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes(StandardCharsets.UTF_8));
    }

    public String generate(Client client, User user, Set<String> scopes, Instant expiresAt) {
        Instant now = Instant.now();
        String subject = user != null ? user.getUsername() : client.getClientId();

        return Jwts.builder()
                .id(UUID.randomUUID().toString())
                .issuer(jwtProperties.getIssuer())
                .subject(subject)
                .audience().add(client.getClientId()).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(expiresAt))
                .claim("client_id", client.getClientId())
                .claim("scope", String.join(" ", scopes))
                .claim("token_type", "access_token")
                .signWith(signingKey, Jwts.SIG.HS256)
                .compact();
    }
}
