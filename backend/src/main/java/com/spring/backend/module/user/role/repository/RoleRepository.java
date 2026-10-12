package com.spring.backend.module.user.role.repository;

import com.spring.backend.module.user.role.entity.RoleEntity;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {

    boolean existsByName(String name);

    Optional<RoleEntity> findByName(String name);

    @EntityGraph(attributePaths = "permissions")
    Optional<RoleEntity> findWithPermissionsById(Long id);

    @Override
    @EntityGraph(attributePaths = "permissions")
    List<RoleEntity> findAll();

    @Override
    @EntityGraph(attributePaths = "permissions")
    List<RoleEntity> findAllById(Iterable<Long> ids);
}
