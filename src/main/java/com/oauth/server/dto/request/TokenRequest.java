package com.oauth.server.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.HashMap;
import java.util.Map;

public class TokenRequest {

    @NotBlank
    @JsonProperty("grant_type")
    private String grantType;

    private String code;

    @JsonProperty("redirect_uri")
    private String redirectUri;

    @JsonProperty("client_id")
    private String clientId;

    @JsonProperty("client_secret")
    private String clientSecret;

    @JsonProperty("refresh_token")
    private String refreshToken;

    private String username;

    private String password;

    private String scope;

    public String getGrantType() {
        return grantType;
    }

    public void setGrantType(String grantType) {
        this.grantType = grantType;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Map<String, String> toParameters() {
        Map<String, String> parameters = new HashMap<>();
        putIfPresent(parameters, "grant_type", grantType);
        putIfPresent(parameters, "code", code);
        putIfPresent(parameters, "redirect_uri", redirectUri);
        putIfPresent(parameters, "client_id", clientId);
        putIfPresent(parameters, "client_secret", clientSecret);
        putIfPresent(parameters, "refresh_token", refreshToken);
        putIfPresent(parameters, "username", username);
        putIfPresent(parameters, "password", password);
        putIfPresent(parameters, "scope", scope);
        return parameters;
    }

    private void putIfPresent(Map<String, String> parameters, String key, String value) {
        if (value != null && !value.isBlank()) {
            parameters.put(key, value);
        }
    }
}
