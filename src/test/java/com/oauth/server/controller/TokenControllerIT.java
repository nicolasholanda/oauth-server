package com.oauth.server.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.autoconfigure.AutoConfigureMockMvc;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class TokenControllerIT {

    private static final String DEMO_BASIC = "Basic " + base64("demo-client:secret");
    private static final String PUBLIC_BASIC = "Basic " + base64("public-client:");

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void clientCredentialsGrantIssuesAccessTokenWithoutRefresh() throws Exception {
        mockMvc.perform(post("/oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, DEMO_BASIC)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials")
                        .param("scope", "read"))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"))
                .andExpect(jsonPath("$.expires_in").isNumber())
                .andExpect(jsonPath("$.scope").value("read"))
                .andExpect(jsonPath("$.refresh_token").doesNotExist());
    }

    @Test
    void passwordGrantIssuesAccessAndRefreshToken() throws Exception {
        mockMvc.perform(post("/oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, DEMO_BASIC)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", "demo-user")
                        .param("password", "secret")
                        .param("scope", "read write"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(jsonPath("$.token_type").value("Bearer"));
    }

    @Test
    void refreshTokenGrantRotatesTokens() throws Exception {
        MvcResult initial = mockMvc.perform(post("/oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, DEMO_BASIC)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "password")
                        .param("username", "demo-user")
                        .param("password", "secret")
                        .param("scope", "read"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(initial.getResponse().getContentAsString());
        String refreshToken = body.get("refresh_token").asText();

        MvcResult rotated = mockMvc.perform(post("/oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, DEMO_BASIC)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "refresh_token")
                        .param("refresh_token", refreshToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.access_token").isNotEmpty())
                .andExpect(jsonPath("$.refresh_token").isNotEmpty())
                .andReturn();

        JsonNode rotatedBody = objectMapper.readTree(rotated.getResponse().getContentAsString());
        assertThat(rotatedBody.get("refresh_token").asText()).isNotEqualTo(refreshToken);
    }

    @Test
    void rejectsInvalidClientCredentialsWith401() throws Exception {
        String badAuth = "Basic " + base64("demo-client:wrong");
        mockMvc.perform(post("/oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, badAuth)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isUnauthorized())
                .andExpect(header().exists(HttpHeaders.WWW_AUTHENTICATE))
                .andExpect(jsonPath("$.error").value("invalid_client"));
    }

    @Test
    void rejectsUnknownGrantType() throws Exception {
        mockMvc.perform(post("/oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, DEMO_BASIC)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "magic"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_grant_type"));
    }

    @Test
    void rejectsPublicClientUsingClientCredentials() throws Exception {
        mockMvc.perform(post("/oauth/token")
                        .header(HttpHeaders.AUTHORIZATION, PUBLIC_BASIC)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "client_credentials"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unauthorized_client"));
    }

    private static String base64(String raw) {
        return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }
}
