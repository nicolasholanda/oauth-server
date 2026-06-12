package com.oauth.server.service.strategy;

import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.exception.OAuth2ErrorCode;
import com.oauth.server.exception.OAuth2Exception;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.List;
import java.util.Map;

@Component
public class GrantStrategyFactory {

    private final Map<GrantType, GrantStrategy> strategies;

    public GrantStrategyFactory(List<GrantStrategy> grantStrategies) {
        Map<GrantType, GrantStrategy> map = new EnumMap<>(GrantType.class);
        for (GrantStrategy strategy : grantStrategies) {
            map.put(strategy.getGrantType(), strategy);
        }
        this.strategies = Map.copyOf(map);
    }

    public GrantStrategy get(GrantType grantType) {
        GrantStrategy strategy = strategies.get(grantType);
        if (strategy == null) {
            throw new OAuth2Exception(OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE, grantType.getValue());
        }
        return strategy;
    }

    public GrantStrategy get(String grantTypeValue) {
        GrantType grantType = GrantType.fromValue(grantTypeValue)
                .orElseThrow(() -> new OAuth2Exception(OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE, grantTypeValue));
        return get(grantType);
    }
}
