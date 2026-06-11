package com.oauth.server.controller;

import com.oauth.server.domain.entity.AccessToken;
import com.oauth.server.domain.entity.RefreshToken;
import com.oauth.server.domain.enums.TokenType;
import com.oauth.server.dto.request.TokenRequest;
import com.oauth.server.dto.response.TokenResponse;
import com.oauth.server.service.TokenService;
import com.oauth.server.service.strategy.GrantStrategy;
import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/oauth/token")
public class TokenController {

    private final TokenService tokenService;

    public TokenController(TokenService tokenService) {
        this.tokenService = tokenService;
    }

    @PostMapping(consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    public ResponseEntity<TokenResponse> issueToken(
            @RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorizationHeader,
            @Valid @ModelAttribute TokenRequest request) {
        GrantStrategy.Result result = tokenService.issueToken(authorizationHeader, request.toParameters());
        TokenResponse response = toResponse(result);
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .header(HttpHeaders.PRAGMA, "no-cache")
                .body(response);
    }

    private TokenResponse toResponse(GrantStrategy.Result result) {
        AccessToken accessToken = result.accessToken();
        RefreshToken refreshToken = result.refreshToken();
        long expiresIn = Math.max(0, accessToken.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());
        return new TokenResponse(
                accessToken.getTokenValue(),
                TokenType.BEARER.getValue(),
                expiresIn,
                refreshToken != null ? refreshToken.getTokenValue() : null,
                formatScopes(result.grantedScopes())
        );
    }

    private String formatScopes(Set<String> scopes) {
        if (scopes == null || scopes.isEmpty()) {
            return null;
        }
        return scopes.stream().sorted().collect(Collectors.joining(" "));
    }
}
