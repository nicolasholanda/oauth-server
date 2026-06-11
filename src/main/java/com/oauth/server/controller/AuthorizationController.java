package com.oauth.server.controller;

import com.oauth.server.dto.request.AuthorizeRequest;
import com.oauth.server.service.AuthorizationService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;

@RestController
@RequestMapping("/oauth/authorize")
public class AuthorizationController {

    private final AuthorizationService authorizationService;

    public AuthorizationController(AuthorizationService authorizationService) {
        this.authorizationService = authorizationService;
    }

    @GetMapping
    public ResponseEntity<Void> authorizeGet(@Valid @ModelAttribute AuthorizeRequest request) {
        return authorize(request);
    }

    @PostMapping
    public ResponseEntity<Void> authorizePost(@Valid @ModelAttribute AuthorizeRequest request) {
        return authorize(request);
    }

    private ResponseEntity<Void> authorize(AuthorizeRequest request) {
        AuthorizationService.Result result = authorizationService.authorize(request.toParameters());
        URI location = buildRedirect(result);
        return ResponseEntity.status(HttpStatus.FOUND).location(location).build();
    }

    private URI buildRedirect(AuthorizationService.Result result) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(result.redirectUri())
                .queryParam("code", result.authorizationCode().getCode());
        if (result.state() != null && !result.state().isBlank()) {
            builder.queryParam("state", result.state());
        }
        return builder.build(true).toUri();
    }
}
