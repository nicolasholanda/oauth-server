package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.RefreshToken;
import com.oauth.server.domain.entity.User;
import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.repository.RefreshTokenRepository;
import com.oauth.server.service.generator.CodeGenerator;
import com.oauth.server.service.generator.TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class RefreshTokenGrantStrategy implements GrantStrategy {

    private final RefreshTokenRepository refreshTokenRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final TokenGenerator tokenGenerator;
    private final CodeGenerator codeGenerator;

    public RefreshTokenGrantStrategy(
            RefreshTokenRepository refreshTokenRepository,
            AccessTokenRepository accessTokenRepository,
            TokenGenerator tokenGenerator,
            CodeGenerator codeGenerator) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.tokenGenerator = tokenGenerator;
        this.codeGenerator = codeGenerator;
    }

    @Override
    public GrantType getGrantType() {
        return GrantType.REFRESH_TOKEN;
    }

    @Override
    @Transactional
    public Result issue(Client client, Map<String, String> parameters) {
        String refreshTokenValue = requireParam(parameters, "refresh_token");

        RefreshToken existing = refreshTokenRepository.findByTokenValue(refreshTokenValue)
                .orElseThrow(() -> new IllegalArgumentException("invalid_grant: refresh token not found"));

        if (!existing.isActive()) {
            throw new IllegalArgumentException("invalid_grant: refresh token is expired or revoked");
        }
        if (!Objects.equals(existing.getClient().getId(), client.getId())) {
            throw new IllegalArgumentException("invalid_grant: refresh token was issued to a different client");
        }

        Set<String> originalScopes = new HashSet<>(existing.getScopes());
        Set<String> requestedScopes = parseScopes(parameters.get("scope"));
        Set<String> grantedScopes = resolveScopes(originalScopes, requestedScopes);

        existing.setRevoked(true);
        if (existing.getAccessToken() != null) {
            AccessToken previousAccess = existing.getAccessToken();
            previousAccess.setRevoked(true);
            accessTokenRepository.save(previousAccess);
        }
        refreshTokenRepository.save(existing);

        User user = existing.getUser();
        Instant now = Instant.now();
        Instant accessExpiry = now.plusSeconds(client.getAccessTokenTtlSeconds());

        AccessToken accessToken = new AccessToken();
        accessToken.setClient(client);
        accessToken.setUser(user);
        accessToken.setScopes(grantedScopes);
        accessToken.setExpiresAt(accessExpiry);
        accessToken.setTokenValue(tokenGenerator.generate(client, user, grantedScopes, accessExpiry));
        accessToken = accessTokenRepository.save(accessToken);

        RefreshToken rotated = new RefreshToken();
        rotated.setClient(client);
        rotated.setUser(user);
        rotated.setAccessToken(accessToken);
        rotated.setScopes(grantedScopes);
        rotated.setExpiresAt(now.plusSeconds(client.getRefreshTokenTtlSeconds()));
        rotated.setTokenValue(codeGenerator.generate());
        rotated = refreshTokenRepository.save(rotated);

        return new Result(accessToken, rotated, grantedScopes);
    }

    private String requireParam(Map<String, String> parameters, String name) {
        String value = parameters.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("invalid_request: missing required parameter '" + name + "'");
        }
        return value;
    }

    private Set<String> parseScopes(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(raw.trim().split("\\s+"))
                .filter(s -> !s.isBlank())
                .collect(Collectors.toCollection(HashSet::new));
    }

    private Set<String> resolveScopes(Set<String> originalScopes, Set<String> requested) {
        if (requested.isEmpty()) {
            return new HashSet<>(originalScopes);
        }
        for (String scope : requested) {
            if (!originalScopes.contains(scope)) {
                throw new IllegalArgumentException("invalid_scope: '" + scope + "' was not in the original grant");
            }
        }
        return requested;
    }
}
