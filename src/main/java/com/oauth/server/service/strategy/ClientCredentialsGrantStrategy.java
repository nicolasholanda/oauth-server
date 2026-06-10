package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.Scope;
import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.service.generator.TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ClientCredentialsGrantStrategy implements GrantStrategy {

    private final AccessTokenRepository accessTokenRepository;
    private final TokenGenerator tokenGenerator;

    public ClientCredentialsGrantStrategy(
            AccessTokenRepository accessTokenRepository,
            TokenGenerator tokenGenerator) {
        this.accessTokenRepository = accessTokenRepository;
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public GrantType getGrantType() {
        return GrantType.CLIENT_CREDENTIALS;
    }

    @Override
    @Transactional
    public Result issue(Client client, Map<String, String> parameters) {
        if (!client.isConfidential()) {
            throw new IllegalArgumentException("unauthorized_client: only confidential clients may use client_credentials");
        }

        Set<String> clientScopeNames = client.getScopes().stream()
                .map(Scope::getName)
                .collect(Collectors.toSet());

        Set<String> requestedScopes = parseScopes(parameters.get("scope"));
        Set<String> grantedScopes = resolveScopes(clientScopeNames, requestedScopes);

        Instant now = Instant.now();
        Instant accessExpiry = now.plusSeconds(client.getAccessTokenTtlSeconds());

        AccessToken accessToken = new AccessToken();
        accessToken.setClient(client);
        accessToken.setUser(null);
        accessToken.setScopes(grantedScopes);
        accessToken.setExpiresAt(accessExpiry);
        accessToken.setTokenValue(tokenGenerator.generate(client, null, grantedScopes, accessExpiry));
        accessToken = accessTokenRepository.save(accessToken);

        return new Result(accessToken, null, grantedScopes);
    }

    private Set<String> parseScopes(String raw) {
        if (raw == null || raw.isBlank()) {
            return Set.of();
        }
        return Arrays.stream(raw.trim().split("\\s+"))
                .filter(s -> !s.isBlank())
                .collect(Collectors.toCollection(HashSet::new));
    }

    private Set<String> resolveScopes(Set<String> clientScopes, Set<String> requested) {
        if (requested.isEmpty()) {
            return new HashSet<>(clientScopes);
        }
        for (String scope : requested) {
            if (!clientScopes.contains(scope)) {
                throw new IllegalArgumentException("invalid_scope: '" + scope + "' is not allowed for this client");
            }
        }
        return requested;
    }
}
