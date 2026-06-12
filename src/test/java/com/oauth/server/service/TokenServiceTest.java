package com.oauth.server.service;

import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.enums.ClientType;
import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.exception.OAuth2ErrorCode;
import com.oauth.server.exception.OAuth2Exception;
import com.oauth.server.service.strategy.GrantStrategy;
import com.oauth.server.service.strategy.GrantStrategyFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private ClientAuthenticationService clientAuthenticationService;
    @Mock
    private GrantStrategyFactory grantStrategyFactory;
    @Mock
    private GrantStrategy strategy;

    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService(clientAuthenticationService, grantStrategyFactory);
    }

    @Test
    void rejectsMissingGrantType() {
        assertThatThrownBy(() -> tokenService.issueToken(null, Map.of()))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_REQUEST));
    }

    @Test
    void rejectsUnknownGrantType() {
        assertThatThrownBy(() -> tokenService.issueToken(null, Map.of("grant_type", "magic")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.UNSUPPORTED_GRANT_TYPE));
    }

    @Test
    void rejectsClientNotAuthorizedForGrantType() {
        Client client = client(Set.of(GrantType.AUTHORIZATION_CODE));
        when(clientAuthenticationService.authenticate(any(), any())).thenReturn(client);

        assertThatThrownBy(() -> tokenService.issueToken(null,
                Map.of("grant_type", "client_credentials")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.UNAUTHORIZED_CLIENT));
    }

    @Test
    void dispatchesToTheMatchingStrategy() {
        Client client = client(Set.of(GrantType.CLIENT_CREDENTIALS));
        when(clientAuthenticationService.authenticate(any(), any())).thenReturn(client);
        when(grantStrategyFactory.get(eq(GrantType.CLIENT_CREDENTIALS))).thenReturn(strategy);
        GrantStrategy.Result expected = new GrantStrategy.Result(null, null, Set.of("read"));
        when(strategy.issue(eq(client), any())).thenReturn(expected);

        GrantStrategy.Result actual = tokenService.issueToken("Basic xyz",
                Map.of("grant_type", "client_credentials"));

        assertThat(actual).isSameAs(expected);
    }

    private Client client(Set<GrantType> grants) {
        Client client = new Client();
        client.setClientId("c");
        client.setClientType(ClientType.CONFIDENTIAL);
        client.setGrantTypes(new HashSet<>(grants));
        return client;
    }
}
