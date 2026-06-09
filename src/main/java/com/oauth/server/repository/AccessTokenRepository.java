package com.oauth.server.repository;

import com.oauth.server.domain.entity.AccessToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface AccessTokenRepository extends JpaRepository<AccessToken, Long> {

    Optional<AccessToken> findByTokenValue(String tokenValue);

    @Modifying
    @Query("UPDATE AccessToken at SET at.revoked = true WHERE at.client.id = :clientId AND at.user.id = :userId AND at.revoked = false")
    int revokeAllForClientAndUser(@Param("clientId") Long clientId, @Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM AccessToken at WHERE at.expiresAt < :now")
    int deleteAllExpired(@Param("now") Instant now);
}
