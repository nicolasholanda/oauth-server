package com.oauth.server.service;

import com.oauth.server.domain.entity.AuthorizationCode;
import com.oauth.server.domain.entity.Client;
import com.oauth.server.domain.entity.Scope;
import com.oauth.server.domain.entity.User;
import com.oauth.server.domain.enums.GrantType;
import com.oauth.server.domain.enums.ResponseType;
import com.oauth.server.exception.OAuth2ErrorCode;
import com.oauth.server.exception.OAuth2Exception;
import com.oauth.server.repository.AuthorizationCodeRepository;
import com.oauth.server.repository.ClientRepository;
import com.oauth.server.repository.UserRepository;
import com.oauth.server.service.generator.CodeGenerator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class AuthorizationService {

    private final ClientRepository clientRepository;
    private final UserRepository userRepository;
    private final AuthorizationCodeRepository authorizationCodeRepository;
    private final CodeGenerator codeGenerator;
    private final long authorizationCodeTtlSeconds;

    public AuthorizationService(
            ClientRepository clientRepository,
            UserRepository userRepository,
            AuthorizationCodeRepository authorizationCodeRepository,
            CodeGenerator codeGenerator,
            @Value("${oauth.authorization-code.ttl-seconds}") long authorizationCodeTtlSeconds) {
        this.clientRepository = clientRepository;
        this.userRepository = userRepository;
        this.authorizationCodeRepository = authorizationCodeRepository;
        this.codeGenerator = codeGenerator;
        this.authorizationCodeTtlSeconds = authorizationCodeTtlSeconds;
    }

    @Transactional
    public Result authorize(Map<String, String> parameters) {
        String responseTypeRaw = requireParam(parameters, "response_type");
        ResponseType responseType = ResponseType.fromValue(responseTypeRaw)
                .orElseThrow(() -> new OAuth2Exception(OAuth2ErrorCode.UNSUPPORTED_RESPONSE_TYPE, responseTypeRaw));
        if (responseType != ResponseType.CODE) {
            throw new OAuth2Exception(OAuth2ErrorCode.UNSUPPORTED_RESPONSE_TYPE, "only 'code' is supported");
        }

        String clientId = requireParam(parameters, "client_id");
        String redirectUri = requireParam(parameters, "redirect_uri");
        String username = requireParam(parameters, "username");
        String state = parameters.get("state");

        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new OAuth2Exception(OAuth2ErrorCode.INVALID_REQUEST, "unknown client_id"));

        if (!client.supportsGrantType(GrantType.AUTHORIZATION_CODE)) {
            throw new OAuth2Exception(OAuth2ErrorCode.UNAUTHORIZED_CLIENT, "client may not use authorization_code grant");
        }
        if (!client.hasRedirectUri(redirectUri)) {
            throw new OAuth2Exception(OAuth2ErrorCode.INVALID_REQUEST, "redirect_uri is not registered for this client");
        }

        Set<String> clientScopes = client.getScopes().stream()
                .map(Scope::getName)
                .collect(Collectors.toSet());
        Set<String> requestedScopes = parseScopes(parameters.get("scope"));
        Set<String> grantedScopes = resolveScopes(clientScopes, requestedScopes);

        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new OAuth2Exception(OAuth2ErrorCode.ACCESS_DENIED, "unknown user"));
        if (!user.isEnabled()) {
            throw new OAuth2Exception(OAuth2ErrorCode.ACCESS_DENIED, "user is disabled");
        }

        Instant now = Instant.now();
        AuthorizationCode authorizationCode = new AuthorizationCode();
        authorizationCode.setCode(codeGenerator.generate());
        authorizationCode.setClient(client);
        authorizationCode.setUser(user);
        authorizationCode.setRedirectUri(redirectUri);
        authorizationCode.setScopes(grantedScopes);
        authorizationCode.setExpiresAt(now.plusSeconds(authorizationCodeTtlSeconds));
        authorizationCode = authorizationCodeRepository.save(authorizationCode);

        return new Result(authorizationCode, state, redirectUri);
    }

    private String requireParam(Map<String, String> parameters, String name) {
        String value = parameters.get(name);
        if (value == null || value.isBlank()) {
            throw new OAuth2Exception(OAuth2ErrorCode.INVALID_REQUEST, "missing required parameter '" + name + "'");
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
                throw new OAuth2Exception(OAuth2ErrorCode.INVALID_SCOPE, "'" + scope + "' is not allowed for this client");
            }
        }
        return requested;
    }

    public record Result(AuthorizationCode authorizationCode, String state, String redirectUri) {
    }
}
