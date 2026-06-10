package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.RefreshToken;
import com.oauth.server.domain.entity.Scope;
import com.oauth.server.domain.entity.User;
import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.repository.RefreshTokenRepository;
import com.oauth.server.repository.UserRepository;
import com.oauth.server.service.generator.CodeGenerator;
import com.oauth.server.service.generator.TokenGenerator;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class PasswordGrantStrategy implements GrantStrategy {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenGenerator tokenGenerator;
    private final CodeGenerator codeGenerator;

    public PasswordGrantStrategy(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            AccessTokenRepository accessTokenRepository,
            RefreshTokenRepository refreshTokenRepository,
            TokenGenerator tokenGenerator,
            CodeGenerator codeGenerator) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenGenerator = tokenGenerator;
        this.codeGenerator = codeGenerator;
    }

    @Override
    public GrantType getGrantType() {
        return GrantType.PASSWORD;
    }

    @Override
    @Transactional
    public Result issue(Client client, Map<String, String> parameters) {
        String username = requireParam(parameters, "username");
        String password = requireParam(parameters, "password");

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("invalid_grant: invalid username or password"));

        if (!user.isEnabled()) {
            throw new IllegalArgumentException("invalid_grant: user is disabled");
        }
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new IllegalArgumentException("invalid_grant: invalid username or password");
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
        accessToken.setUser(user);
        accessToken.setScopes(grantedScopes);
        accessToken.setExpiresAt(accessExpiry);
        accessToken.setTokenValue(tokenGenerator.generate(client, user, grantedScopes, accessExpiry));
        accessToken = accessTokenRepository.save(accessToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setClient(client);
        refreshToken.setUser(user);
        refreshToken.setAccessToken(accessToken);
        refreshToken.setScopes(grantedScopes);
        refreshToken.setExpiresAt(now.plusSeconds(client.getRefreshTokenTtlSeconds()));
        refreshToken.setTokenValue(codeGenerator.generate());
        refreshToken = refreshTokenRepository.save(refreshToken);

        return new Result(accessToken, refreshToken, grantedScopes);
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
