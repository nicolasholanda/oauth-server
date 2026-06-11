package com.oauth.server.dto.request;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

import java.util.HashMap;
import java.util.Map;

public class AuthorizeRequest {

    @NotBlank
    @JsonProperty("response_type")
    private String responseType;

    @NotBlank
    @JsonProperty("client_id")
    private String clientId;

    @NotBlank
    @JsonProperty("redirect_uri")
    private String redirectUri;

    private String scope;

    private String state;

    @NotBlank
    private String username;

    public String getResponseType() {
        return responseType;
    }

    public void setResponseType(String responseType) {
        this.responseType = responseType;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public Map<String, String> toParameters() {
        Map<String, String> parameters = new HashMap<>();
        putIfPresent(parameters, "response_type", responseType);
        putIfPresent(parameters, "client_id", clientId);
        putIfPresent(parameters, "redirect_uri", redirectUri);
        putIfPresent(parameters, "scope", scope);
        putIfPresent(parameters, "state", state);
        putIfPresent(parameters, "username", username);
        return parameters;
    }

    private void putIfPresent(Map<String, String> parameters, String key, String value) {
        if (value != null && !value.isBlank()) {
            parameters.put(key, value);
        }
    }
}
