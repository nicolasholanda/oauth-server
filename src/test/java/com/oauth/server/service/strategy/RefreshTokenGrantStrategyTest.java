package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.RefreshToken;
import com.oauth.server.domain.entity.User;
import com.oauth.server.exception.OAuth2ErrorCode;
import com.oauth.server.exception.OAuth2Exception;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.repository.RefreshTokenRepository;
import com.oauth.server.service.generator.CodeGenerator;
import com.oauth.server.service.generator.TokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RefreshTokenGrantStrategyTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private AccessTokenRepository accessTokenRepository;
    @Mock
    private TokenGenerator tokenGenerator;
    @Mock
    private CodeGenerator codeGenerator;

    private RefreshTokenGrantStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new RefreshTokenGrantStrategy(
                refreshTokenRepository, accessTokenRepository, tokenGenerator, codeGenerator);
    }

    @Test
    void rotatesTokensAndRevokesPrevious() {
        Client client = clientWithId(10L);
        RefreshToken existing = activeRefreshToken(client, Set.of("read", "write"));
        when(refreshTokenRepository.findByTokenValue("rt-old")).thenReturn(Optional.of(existing));
        when(accessTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenGenerator.generate(any(), any(), any(), any())).thenReturn("jwt-new");
        when(codeGenerator.generate()).thenReturn("rt-new");

        GrantStrategy.Result result = strategy.issue(client, Map.of("refresh_token", "rt-old"));

        assertThat(result.accessToken().getTokenValue()).isEqualTo("jwt-new");
        assertThat(result.refreshToken().getTokenValue()).isEqualTo("rt-new");
        assertThat(existing.isRevoked()).isTrue();
        assertThat(existing.getAccessToken().isRevoked()).isTrue();
    }

    @Test
    void narrowsScopesWhenRequested() {
        Client client = clientWithId(10L);
        RefreshToken existing = activeRefreshToken(client, Set.of("read", "write"));
        when(refreshTokenRepository.findByTokenValue("rt-old")).thenReturn(Optional.of(existing));
        when(accessTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenGenerator.generate(any(), any(), any(), any())).thenReturn("jwt-new");
        when(codeGenerator.generate()).thenReturn("rt-new");

        GrantStrategy.Result result = strategy.issue(client, Map.of(
                "refresh_token", "rt-old",
                "scope", "read"));

        assertThat(result.grantedScopes()).containsExactly("read");
        ArgumentCaptor<AccessToken> captor = ArgumentCaptor.forClass(AccessToken.class);
        verify(accessTokenRepository).save(captor.capture());
        assertThat(captor.getValue().getScopes()).containsExactly("read");
    }

    @Test
    void rejectsScopeNotInOriginalGrant() {
        Client client = clientWithId(10L);
        RefreshToken existing = activeRefreshToken(client, Set.of("read"));
        when(refreshTokenRepository.findByTokenValue("rt-old")).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> strategy.issue(client, Map.of(
                "refresh_token", "rt-old",
                "scope", "admin")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_SCOPE));
    }

    @Test
    void rejectsUnknownRefreshToken() {
        Client client = clientWithId(10L);
        when(refreshTokenRepository.findByTokenValue(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> strategy.issue(client, Map.of("refresh_token", "missing")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsRevokedRefreshToken() {
        Client client = clientWithId(10L);
        RefreshToken existing = activeRefreshToken(client, Set.of("read"));
        existing.setRevoked(true);
        when(refreshTokenRepository.findByTokenValue("rt-old")).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> strategy.issue(client, Map.of("refresh_token", "rt-old")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsRefreshTokenIssuedToAnotherClient() {
        Client requester = clientWithId(10L);
        Client otherClient = clientWithId(99L);
        RefreshToken existing = activeRefreshToken(otherClient, Set.of("read"));
        when(refreshTokenRepository.findByTokenValue("rt-old")).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> strategy.issue(requester, Map.of("refresh_token", "rt-old")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    private Client clientWithId(long id) {
        Client client = new Client();
        client.setId(id);
        client.setClientId("client-" + id);
        client.setAccessTokenTtlSeconds(3600L);
        client.setRefreshTokenTtlSeconds(86400L);
        return client;
    }

    private RefreshToken activeRefreshToken(Client client, Set<String> scopes) {
        AccessToken previous = new AccessToken();
        previous.setClient(client);
        previous.setTokenValue("jwt-old");
        previous.setExpiresAt(Instant.now().plusSeconds(3600));
        RefreshToken token = new RefreshToken();
        token.setTokenValue("rt-old");
        token.setClient(client);
        User user = new User();
        user.setUsername("alice");
        token.setUser(user);
        token.setAccessToken(previous);
        token.setScopes(new HashSet<>(scopes));
        token.setExpiresAt(Instant.now().plusSeconds(86400));
        return token;
    }
}
