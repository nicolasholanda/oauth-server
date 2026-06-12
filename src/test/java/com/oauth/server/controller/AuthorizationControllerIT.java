package com.oauth.server.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.autoconfigure.AutoConfigureMockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationControllerIT {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void issuesAuthorizationCodeViaRedirect() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth/authorize")
                        .param("response_type", "code")
                        .param("client_id", "demo-client")
                        .param("redirect_uri", "http://localhost:3000/callback")
                        .param("scope", "read")
                        .param("state", "xyz123")
                        .param("username", "demo-user"))
                .andExpect(status().isFound())
                .andExpect(header().exists("Location"))
                .andReturn();

        String location = result.getResponse().getHeader("Location");
        assertThat(location).isNotNull();
        assertThat(location).startsWith("http://localhost:3000/callback?");
        assertThat(location).contains("code=");
        assertThat(location).contains("state=xyz123");
    }

    @Test
    void acceptsPostInAdditionToGet() throws Exception {
        mockMvc.perform(post("/oauth/authorize")
                        .param("response_type", "code")
                        .param("client_id", "demo-client")
                        .param("redirect_uri", "http://localhost:3000/callback")
                        .param("username", "demo-user"))
                .andExpect(status().isFound());
    }

    @Test
    void rejectsUnknownClient() throws Exception {
        mockMvc.perform(get("/oauth/authorize")
                        .param("response_type", "code")
                        .param("client_id", "ghost-client")
                        .param("redirect_uri", "http://localhost:3000/callback")
                        .param("username", "demo-user"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void rejectsUnregisteredRedirectUri() throws Exception {
        mockMvc.perform(get("/oauth/authorize")
                        .param("response_type", "code")
                        .param("client_id", "demo-client")
                        .param("redirect_uri", "http://attacker.example/cb")
                        .param("username", "demo-user"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("invalid_request"));
    }

    @Test
    void rejectsUnsupportedResponseType() throws Exception {
        mockMvc.perform(get("/oauth/authorize")
                        .param("response_type", "token")
                        .param("client_id", "demo-client")
                        .param("redirect_uri", "http://localhost:3000/callback")
                        .param("username", "demo-user"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.error").value("unsupported_response_type"));
    }

    @Test
    void rejectsUnknownUser() throws Exception {
        mockMvc.perform(get("/oauth/authorize")
                        .param("response_type", "code")
                        .param("client_id", "demo-client")
                        .param("redirect_uri", "http://localhost:3000/callback")
                        .param("username", "ghost"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.error").value("access_denied"));
    }
}
