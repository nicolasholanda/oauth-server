package com.oauth.server.domain.entity;

import com.oauth.server.domain.enums.ClientType;
import com.oauth.server.domain.enums.GrantType;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Entity;

import java.time.Instant;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

@Entity
@Table(name = "clients")
public class Client {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id", nullable = false, unique = true, length = 100)
    private String clientId;

    @Column(name = "client_secret", length = 200)
    private String clientSecret;

    @Column(nullable = false, length = 200)
    private String name;

    @Enumerated(EnumType.STRING)
    @Column(name = "client_type", nullable = false, length = 20)
    private ClientType clientType;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "client_redirect_uris", joinColumns = @JoinColumn(name = "client_id"))
    @Column(name = "redirect_uri", nullable = false, length = 500)
    private Set<String> redirectUris = new HashSet<>();

    @ElementCollection(fetch = FetchType.EAGER, targetClass = GrantType.class)
    @CollectionTable(name = "client_grant_types", joinColumns = @JoinColumn(name = "client_id"))
    @Enumerated(EnumType.STRING)
    @Column(name = "grant_type", nullable = false, length = 30)
    private Set<GrantType> grantTypes = new HashSet<>();

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "client_scopes",
            joinColumns = @JoinColumn(name = "client_id"),
            inverseJoinColumns = @JoinColumn(name = "scope_id"))
    private Set<Scope> scopes = new HashSet<>();

    @Column(name = "access_token_ttl_seconds", nullable = false)
    private Long accessTokenTtlSeconds;

    @Column(name = "refresh_token_ttl_seconds", nullable = false)
    private Long refreshTokenTtlSeconds;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    public Client() {
    }

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        this.createdAt = now;
        this.updatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        this.updatedAt = Instant.now();
    }

    public boolean isConfidential() {
        return clientType == ClientType.CONFIDENTIAL;
    }

    public boolean supportsGrantType(GrantType grantType) {
        return grantTypes.contains(grantType);
    }

    public boolean hasRedirectUri(String redirectUri) {
        return redirectUris.contains(redirectUri);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public ClientType getClientType() {
        return clientType;
    }

    public void setClientType(ClientType clientType) {
        this.clientType = clientType;
    }

    public Set<String> getRedirectUris() {
        return redirectUris;
    }

    public void setRedirectUris(Set<String> redirectUris) {
        this.redirectUris = redirectUris;
    }

    public Set<GrantType> getGrantTypes() {
        return grantTypes;
    }

    public void setGrantTypes(Set<GrantType> grantTypes) {
        this.grantTypes = grantTypes;
    }

    public Set<Scope> getScopes() {
        return scopes;
    }

    public void setScopes(Set<Scope> scopes) {
        this.scopes = scopes;
    }

    public Long getAccessTokenTtlSeconds() {
        return accessTokenTtlSeconds;
    }

    public void setAccessTokenTtlSeconds(Long accessTokenTtlSeconds) {
        this.accessTokenTtlSeconds = accessTokenTtlSeconds;
    }

    public Long getRefreshTokenTtlSeconds() {
        return refreshTokenTtlSeconds;
    }

    public void setRefreshTokenTtlSeconds(Long refreshTokenTtlSeconds) {
        this.refreshTokenTtlSeconds = refreshTokenTtlSeconds;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof Client client)) return false;
        return Objects.equals(clientId, client.clientId);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId);
    }
}
