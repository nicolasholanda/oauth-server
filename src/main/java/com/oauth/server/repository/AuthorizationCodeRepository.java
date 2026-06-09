package com.oauth.server.repository;

import com.oauth.server.domain.entity.AuthorizationCode;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, Long> {

    Optional<AuthorizationCode> findByCode(String code);

    @Modifying
    @Query("DELETE FROM AuthorizationCode ac WHERE ac.expiresAt < :now")
    int deleteAllExpired(@Param("now") Instant now);
}
