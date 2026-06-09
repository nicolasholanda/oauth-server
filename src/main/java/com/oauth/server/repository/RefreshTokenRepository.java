package com.oauth.server.repository;

import com.oauth.server.domain.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByTokenValue(String tokenValue);

    @Modifying
    @Query("UPDATE RefreshToken rt SET rt.revoked = true WHERE rt.client.id = :clientId AND rt.user.id = :userId AND rt.revoked = false")
    int revokeAllForClientAndUser(@Param("clientId") Long clientId, @Param("userId") Long userId);

    @Modifying
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    int deleteAllExpired(@Param("now") Instant now);
}
