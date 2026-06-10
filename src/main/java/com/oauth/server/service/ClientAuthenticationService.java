package com.oauth.server.service;

import com.oauth.server.domain.entity.Client;
import com.oauth.server.repository.ClientRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Service
public class ClientAuthenticationService {

    private static final String BASIC_PREFIX = "Basic ";

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    public ClientAuthenticationService(ClientRepository clientRepository, PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Client authenticate(String authorizationHeader, Map<String, String> parameters) {
        Credentials credentials = extractCredentials(authorizationHeader, parameters);

        Client client = clientRepository.findByClientId(credentials.clientId())
                .orElseThrow(() -> new IllegalArgumentException("invalid_client: unknown client_id"));

        if (client.isConfidential()) {
            if (credentials.clientSecret() == null) {
                throw new IllegalArgumentException("invalid_client: client_secret required for confidential client");
            }
            if (client.getClientSecret() == null
                    || !passwordEncoder.matches(credentials.clientSecret(), client.getClientSecret())) {
                throw new IllegalArgumentException("invalid_client: client authentication failed");
            }
        }

        return client;
    }

    public Client authenticatePublic(String clientId) {
        Client client = clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new IllegalArgumentException("invalid_client: unknown client_id"));
        if (client.isConfidential()) {
            throw new IllegalArgumentException("invalid_client: client requires authentication");
        }
        return client;
    }

    private Credentials extractCredentials(String authorizationHeader, Map<String, String> parameters) {
        if (authorizationHeader != null && authorizationHeader.startsWith(BASIC_PREFIX)) {
            String encoded = authorizationHeader.substring(BASIC_PREFIX.length()).trim();
            String decoded;
            try {
                decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
            } catch (IllegalArgumentException ex) {
                throw new IllegalArgumentException("invalid_client: malformed Basic authentication header");
            }
            int separator = decoded.indexOf(':');
            if (separator < 0) {
                throw new IllegalArgumentException("invalid_client: malformed Basic authentication header");
            }
            String clientId = decoded.substring(0, separator);
            String clientSecret = decoded.substring(separator + 1);
            return new Credentials(clientId, clientSecret.isEmpty() ? null : clientSecret);
        }

        String clientId = parameters.get("client_id");
        String clientSecret = parameters.get("client_secret");
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("invalid_client: missing client_id");
        }
        return new Credentials(clientId, (clientSecret == null || clientSecret.isBlank()) ? null : clientSecret);
    }

    private record Credentials(String clientId, String clientSecret) {
    }
}
