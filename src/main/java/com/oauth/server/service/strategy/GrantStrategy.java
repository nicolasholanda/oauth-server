package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.RefreshToken;
import com.oauth.server.domain.enums.GrantType;

import java.util.Map;
import java.util.Set;

public interface GrantStrategy {

    GrantType getGrantType();

    Result issue(Client client, Map<String, String> parameters);

    record Result(AccessToken accessToken, RefreshToken refreshToken, Set<String> grantedScopes) {

        public boolean hasRefreshToken() {
            return refreshToken != null;
        }
    }
}
