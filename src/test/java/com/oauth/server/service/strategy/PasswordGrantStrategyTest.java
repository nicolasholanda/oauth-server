package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.Scope;
import com.oauth.server.domain.entity.User;
import com.oauth.server.domain.enums.ClientType;
import com.oauth.server.exception.OAuth2ErrorCode;
import com.oauth.server.exception.OAuth2Exception;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.repository.RefreshTokenRepository;
import com.oauth.server.repository.UserRepository;
import com.oauth.server.service.generator.CodeGenerator;
import com.oauth.server.service.generator.TokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class PasswordGrantStrategyTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AccessTokenRepository accessTokenRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private TokenGenerator tokenGenerator;
    @Mock
    private CodeGenerator codeGenerator;

    private PasswordGrantStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new PasswordGrantStrategy(
                userRepository, passwordEncoder, accessTokenRepository,
                refreshTokenRepository, tokenGenerator, codeGenerator);
    }

    @Test
    void issuesAccessAndRefreshTokenForValidCredentials() {
        Client client = client("read");
        User user = enabledUser("alice", "hash");
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("secret", "hash")).thenReturn(true);
        when(accessTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenGenerator.generate(any(), any(), any(), any())).thenReturn("jwt-token");
        when(codeGenerator.generate()).thenReturn("refresh-opaque");

        GrantStrategy.Result result = strategy.issue(client, Map.of(
                "username", "alice",
                "password", "secret",
                "scope", "read"));

        assertThat(result.accessToken().getTokenValue()).isEqualTo("jwt-token");
        assertThat(result.refreshToken().getTokenValue()).isEqualTo("refresh-opaque");
        assertThat(result.grantedScopes()).containsExactly("read");
    }

    @Test
    void rejectsUnknownUser() {
        Client client = client("read");
        when(userRepository.findByUsername(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> strategy.issue(client, Map.of(
                "username", "ghost",
                "password", "secret")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsDisabledUser() {
        Client client = client("read");
        User user = enabledUser("alice", "hash");
        user.setEnabled(false);
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> strategy.issue(client, Map.of(
                "username", "alice",
                "password", "secret")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsWrongPassword() {
        Client client = client("read");
        User user = enabledUser("alice", "hash");
        when(userRepository.findByUsername("alice")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong", "hash")).thenReturn(false);

        assertThatThrownBy(() -> strategy.issue(client, Map.of(
                "username", "alice",
                "password", "wrong")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsMissingUsername() {
        Client client = client("read");

        assertThatThrownBy(() -> strategy.issue(client, Map.of("password", "secret")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_REQUEST));
    }

    private Client client(String... scopeNames) {
        Client client = new Client();
        client.setId(1L);
        client.setClientId("demo-client");
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

    private User enabledUser(String username, String hash) {
        User user = new User();
        user.setUsername(username);
        user.setPasswordHash(hash);
        user.setEnabled(true);
        return user;
    }
}
