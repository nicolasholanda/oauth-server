package com.oauth.server.service;

import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.service.strategy.GrantStrategy;
import com.oauth.server.service.strategy.GrantStrategyFactory;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class TokenService {

    private final ClientAuthenticationService clientAuthenticationService;
    private final GrantStrategyFactory grantStrategyFactory;

    public TokenService(
            ClientAuthenticationService clientAuthenticationService,
            GrantStrategyFactory grantStrategyFactory) {
        this.clientAuthenticationService = clientAuthenticationService;
        this.grantStrategyFactory = grantStrategyFactory;
    }

    public GrantStrategy.Result issueToken(String authorizationHeader, Map<String, String> parameters) {
        String grantTypeRaw = parameters.get("grant_type");
        if (grantTypeRaw == null || grantTypeRaw.isBlank()) {
            throw new IllegalArgumentException("invalid_request: missing required parameter 'grant_type'");
        }
        GrantType grantType = GrantType.fromValue(grantTypeRaw)
                .orElseThrow(() -> new IllegalArgumentException("unsupported_grant_type: " + grantTypeRaw));

        Client client = clientAuthenticationService.authenticate(authorizationHeader, parameters);

        if (!client.supportsGrantType(grantType)) {
            throw new IllegalArgumentException("unauthorized_client: client may not use grant type '" + grantType.getValue() + "'");
        }

        GrantStrategy strategy = grantStrategyFactory.get(grantType);
        return strategy.issue(client, parameters);
    }
}
