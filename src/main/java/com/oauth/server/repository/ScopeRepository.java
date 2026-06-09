package com.oauth.server.repository;

import com.oauth.server.domain.entity.Scope;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.Set;

@Repository
public interface ScopeRepository extends JpaRepository<Scope, Long> {

    Optional<Scope> findByName(String name);

    List<Scope> findByNameIn(Set<String> names);
}
