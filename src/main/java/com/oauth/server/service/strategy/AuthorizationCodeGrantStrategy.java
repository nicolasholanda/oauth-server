package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.AuthorizationCode;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.RefreshToken;
import com.oauth.server.domain.entity.User;
import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.repository.AuthorizationCodeRepository;
import com.oauth.server.repository.RefreshTokenRepository;
import com.oauth.server.service.generator.CodeGenerator;
import com.oauth.server.service.generator.TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

@Component
public class AuthorizationCodeGrantStrategy implements GrantStrategy {

    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final AccessTokenRepository accessTokenRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TokenGenerator tokenGenerator;
    private final CodeGenerator codeGenerator;

    public AuthorizationCodeGrantStrategy(
            AuthorizationCodeRepository authorizationCodeRepository,
            AccessTokenRepository accessTokenRepository,
            RefreshTokenRepository refreshTokenRepository,
            TokenGenerator tokenGenerator,
            CodeGenerator codeGenerator) {
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.accessTokenRepository = accessTokenRepository;
        this.refreshTokenRepository = refreshTokenRepository;
        this.tokenGenerator = tokenGenerator;
        this.codeGenerator = codeGenerator;
    }

    @Override
    public GrantType getGrantType() {
        return GrantType.AUTHORIZATION_CODE;
    }

    @Override
    @Transactional
    public Result issue(Client client, Map<String, String> parameters) {
        String code = requireParam(parameters, "code");
        String redirectUri = requireParam(parameters, "redirect_uri");

        AuthorizationCode authorizationCode = authorizationCodeRepository.findByCode(code)
                .orElseThrow(() -> new IllegalArgumentException("invalid_grant: authorization code not found"));

        if (!authorizationCode.isUsable()) {
            throw new IllegalArgumentException("invalid_grant: authorization code is expired or already used");
        }
        if (!Objects.equals(authorizationCode.getClient().getId(), client.getId())) {
            throw new IllegalArgumentException("invalid_grant: authorization code was issued to a different client");
        }
        if (!Objects.equals(authorizationCode.getRedirectUri(), redirectUri)) {
            throw new IllegalArgumentException("invalid_grant: redirect_uri does not match the one used during authorization");
        }

        authorizationCode.setUsed(true);
        authorizationCodeRepository.save(authorizationCode);

        Set<String> scopes = new HashSet<>(authorizationCode.getScopes());
        User user = authorizationCode.getUser();

        Instant now = Instant.now();
        Instant accessExpiry = now.plusSeconds(client.getAccessTokenTtlSeconds());

        AccessToken accessToken = new AccessToken();
        accessToken.setClient(client);
        accessToken.setUser(user);
        accessToken.setScopes(scopes);
        accessToken.setExpiresAt(accessExpiry);
        accessToken.setTokenValue(tokenGenerator.generate(client, user, scopes, accessExpiry));
        accessToken = accessTokenRepository.save(accessToken);

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setClient(client);
        refreshToken.setUser(user);
        refreshToken.setAccessToken(accessToken);
        refreshToken.setScopes(scopes);
        refreshToken.setExpiresAt(now.plusSeconds(client.getRefreshTokenTtlSeconds()));
        refreshToken.setTokenValue(codeGenerator.generate());
        refreshToken = refreshTokenRepository.save(refreshToken);

        return new Result(accessToken, refreshToken, scopes);
    }

    private String requireParam(Map<String, String> parameters, String name) {
        String value = parameters.get(name);
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("invalid_request: missing required parameter '" + name + "'");
        }
        return value;
    }
}
