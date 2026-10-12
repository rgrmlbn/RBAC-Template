package com.spring.backend.module.user.user.repository;

import com.spring.backend.module.user.user.entity.UserEntity;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    boolean existsByEmail(String email);
    Optional<UserEntity> findByEmail(String email);

    // NEW: loads roles + permissions in one query (used by UserDetailsServiceImpl / JwtFilter)
    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<UserEntity> findWithRolesByEmail(String email);

    // NEW: loads roles in one query (used by UserServiceImpl)
    @EntityGraph(attributePaths = "roles")
    Optional<UserEntity> findWithRolesById(Long id);

    // NEW: overrides findAll() so listing users doesn't trigger one query per user for roles
    @Override
    @EntityGraph(attributePaths = "roles")
    List<UserEntity> findAll();

    // NEW: used to protect the last SUPER_ADMIN and to seed the first admin
    long countByRolesName(String name);

    // NEW: used to block deleting a role that is still assigned to users
    boolean existsByRolesId(Long roleId);
}