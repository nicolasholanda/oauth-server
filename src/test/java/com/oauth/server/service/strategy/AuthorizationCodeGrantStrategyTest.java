package com.oauth.server.service.strategy;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.AuthorizationCode;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.RefreshToken;
import com.oauth.server.domain.entity.User;
import com.oauth.server.exception.OAuth2ErrorCode;
import com.oauth.server.exception.OAuth2Exception;
import com.oauth.server.repository.AccessTokenRepository;
import com.oauth.server.repository.AuthorizationCodeRepository;
import com.oauth.server.repository.RefreshTokenRepository;
import com.oauth.server.service.generator.CodeGenerator;
import com.oauth.server.service.generator.TokenGenerator;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthorizationCodeGrantStrategyTest {

    @Mock
    private AuthorizationCodeRepository authorizationCodeRepository;
    @Mock
    private AccessTokenRepository accessTokenRepository;
    @Mock
    private RefreshTokenRepository refreshTokenRepository;
    @Mock
    private TokenGenerator tokenGenerator;
    @Mock
    private CodeGenerator codeGenerator;

    private AuthorizationCodeGrantStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new AuthorizationCodeGrantStrategy(
                authorizationCodeRepository,
                accessTokenRepository,
                refreshTokenRepository,
                tokenGenerator,
                codeGenerator);
    }

    @Test
    void issuesAccessAndRefreshTokenWhenCodeIsValid() {
        Client client = clientWithId(10L);
        AuthorizationCode code = validCode(client, "https://app.example/cb", Set.of("read"));
        when(authorizationCodeRepository.findByCode("CODE")).thenReturn(Optional.of(code));
        when(authorizationCodeRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(accessTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(refreshTokenRepository.save(any())).thenAnswer(inv -> inv.getArgument(0));
        when(tokenGenerator.generate(any(), any(), any(), any())).thenReturn("jwt-token");
        when(codeGenerator.generate()).thenReturn("refresh-opaque");

        GrantStrategy.Result result = strategy.issue(client, Map.of(
                "code", "CODE",
                "redirect_uri", "https://app.example/cb"));

        AccessToken accessToken = result.accessToken();
        RefreshToken refreshToken = result.refreshToken();
        assertThat(accessToken.getTokenValue()).isEqualTo("jwt-token");
        assertThat(refreshToken.getTokenValue()).isEqualTo("refresh-opaque");
        assertThat(result.grantedScopes()).containsExactly("read");
        assertThat(code.isUsed()).isTrue();
    }

    @Test
    void rejectsWhenCodeIsUnknown() {
        Client client = clientWithId(10L);
        when(authorizationCodeRepository.findByCode(anyString())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> strategy.issue(client, Map.of(
                "code", "missing",
                "redirect_uri", "https://app.example/cb")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsWhenCodeWasIssuedToAnotherClient() {
        Client requester = clientWithId(10L);
        Client otherClient = clientWithId(99L);
        AuthorizationCode code = validCode(otherClient, "https://app.example/cb", Set.of("read"));
        when(authorizationCodeRepository.findByCode("CODE")).thenReturn(Optional.of(code));

        assertThatThrownBy(() -> strategy.issue(requester, Map.of(
                "code", "CODE",
                "redirect_uri", "https://app.example/cb")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsWhenRedirectUriDoesNotMatch() {
        Client client = clientWithId(10L);
        AuthorizationCode code = validCode(client, "https://app.example/cb", Set.of("read"));
        when(authorizationCodeRepository.findByCode("CODE")).thenReturn(Optional.of(code));

        assertThatThrownBy(() -> strategy.issue(client, Map.of(
                "code", "CODE",
                "redirect_uri", "https://attacker.example/cb")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsWhenCodeIsAlreadyUsed() {
        Client client = clientWithId(10L);
        AuthorizationCode code = validCode(client, "https://app.example/cb", Set.of("read"));
        code.setUsed(true);
        when(authorizationCodeRepository.findByCode("CODE")).thenReturn(Optional.of(code));

        assertThatThrownBy(() -> strategy.issue(client, Map.of(
                "code", "CODE",
                "redirect_uri", "https://app.example/cb")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_GRANT));
    }

    @Test
    void rejectsWhenRequiredParameterMissing() {
        Client client = clientWithId(10L);
        assertThatThrownBy(() -> strategy.issue(client, Map.of("redirect_uri", "https://app.example/cb")))
                .isInstanceOfSatisfying(OAuth2Exception.class,
                        ex -> assertThat(ex.getErrorCode()).isEqualTo(OAuth2ErrorCode.INVALID_REQUEST));
    }

    private Client clientWithId(long id) {
        Client client = new Client();
        client.setId(id);
        client.setClientId("client-" + id);
        client.setAccessTokenTtlSeconds(3600L);
        client.setRefreshTokenTtlSeconds(86400L);
        return client;
    }

    private AuthorizationCode validCode(Client client, String redirectUri, Set<String> scopes) {
        AuthorizationCode code = new AuthorizationCode();
        code.setCode("CODE");
        code.setClient(client);
        User user = new User();
        user.setUsername("alice");
        code.setUser(user);
        code.setRedirectUri(redirectUri);
        code.setScopes(scopes);
        code.setExpiresAt(Instant.now().plusSeconds(300));
        return code;
    }
}
