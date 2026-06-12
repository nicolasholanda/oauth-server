package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.Scope;
import com.oauth.server.domain.enums.ClientType;
import com.oauth.server.exception.OAuth2ErrorCode;
import com.oauth.server.exception.OAuth2Exception;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.service.generator.TokenGenerator;
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
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ClientCredentialsGrantStrategyTest {

    @Mock
    private AccessTokenRepository accessTokenRepository;
    @Mock
    private TokenGenerator tokenGenerator;

    private ClientCredentialsGrantStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new ClientCredentialsGrantStrategy(accessTokenRepository, tokenGenerator);
    }

    @Test
    void issuesAccessTokenWithoutRefreshToken() {
        Client client = confidentialClient("read", "write");
        when(accessTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenGenerator.generate(any(), any(), any(), any())).thenReturn("jwt-token");

        GrantStrategy.Result result = strategy.issue(client, Map.of("scope", "read"));

        assertThat(result.accessToken().getTokenValue()).isEqualTo("jwt-token");
        assertThat(result.refreshToken()).isNull();
        assertThat(result.grantedScopes()).containsExactly("read");
    }

    @Test
    void defaultsToAllClientScopesWhenNoneRequested() {
        Client client = confidentialClient("read", "write");
        when(accessTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenGenerator.generate(any(), any(), any(), any())).thenReturn("jwt-token");

        GrantStrategy.Result result = strategy.issue(client, Map.of());

        assertThat(result.grantedScopes()).containsExactlyInAnyOrder("read", "write");
    }

    @Test
    void rejectsPublicClient() {
        Client client = confidentialClient("read");
        client.setClientType(ClientType.PUBLIC);

        assertThatThrownBy(() -> strategy.issue(client, Map.of()))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.UNAUTHORIZED_CLIENT));
    }

    @Test
    void rejectsScopeNotAllowedForClient() {
        Client client = confidentialClient("read");

        assertThatThrownBy(() -> strategy.issue(client, Map.of("scope", "admin")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_SCOPE));
    }

    private Client confidentialClient(String... scopeNames) {
        Client client = new Client();
        client.setId(1L);
        client.setClientId("svc-client");
        client.setClientType(ClientType.CONFIDENTIAL);
        client.setAccessTokenTtlSeconds(3600L);
        client.setRefreshTokenTtlSeconds(86400L);
        Set<Scope> scopes = new HashSet<>();
        for (String name : scopeNames) {
            scopes.add(new Scope(name, null));
        }
        client.setScopes(scopes);
        return client;
    }
}
