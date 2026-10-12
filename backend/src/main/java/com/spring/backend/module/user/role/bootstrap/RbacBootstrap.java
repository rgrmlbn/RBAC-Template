package com.spring.backend.module.user.role.bootstrap;

import com.spring.backend.module.security.permission.Perm;
import com.spring.backend.module.security.permission.RoleNames;
import com.spring.backend.module.user.permission.entity.PermissionEntity;
import com.spring.backend.module.user.permission.repository.PermissionRepository;

import com.spring.backend.module.user.role.entity.RoleEntity;
import com.spring.backend.module.user.role.repository.RoleRepository;
import com.spring.backend.module.user.user.entity.UserEntity;
import com.spring.backend.module.user.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Runs on every startup, idempotent:
 *  1. inserts any permission declared in Perm that is missing from the DB
 *  2. creates SUPER_ADMIN (all permissions, re-synced each boot) and USER roles
 *  3. creates the first super admin account from config if none exists
 */
@Component
@RequiredArgsConstructor
@Slf4j
public class RbacBootstrap implements ApplicationRunner {

    private final PermissionRepository permissionRepository;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.bootstrap-admin.email:}")
    private String adminEmail;

    @Value("${app.bootstrap-admin.password:}")
    private String adminPassword;

    @Value("${app.bootstrap-admin.name:Super Admin}")
    private String adminName;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        // 1. permissions
        Map<String, PermissionEntity> permissions = new HashMap<>();
        permissionRepository.findAll().forEach(p -> permissions.put(p.getName(), p));
        for (String name : Perm.all()) {
            permissions.computeIfAbsent(name, n -> permissionRepository.save(new PermissionEntity(n)));
        }

        // 2. built-in roles
        RoleEntity superAdmin = roleRepository.findByName(RoleNames.SUPER_ADMIN).orElseGet(() -> {
            RoleEntity r = new RoleEntity();
            r.setName(RoleNames.SUPER_ADMIN);
            r.setDescription("Full access. Cannot be modified or deleted.");
            r.setSystemRole(true);
            return r;
        });
        superAdmin.setPermissions(new HashSet<>(permissions.values()));
        superAdmin = roleRepository.save(superAdmin);

        roleRepository.findByName(RoleNames.USER).orElseGet(() -> {
            RoleEntity r = new RoleEntity();
            r.setName(RoleNames.USER);
            r.setDescription("Default role for registered users.");
            r.setSystemRole(true);
            return roleRepository.save(r);
        });

        // 3. first super admin
        if (!adminEmail.isBlank() && !adminPassword.isBlank()
                && userRepository.countByRolesName(RoleNames.SUPER_ADMIN) == 0
                && !userRepository.existsByEmail(adminEmail)) {
            UserEntity admin = UserEntity.builder()
                    .name(adminName)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .build();
            admin.getRoles().add(superAdmin);
            userRepository.save(admin);
            log.info("Bootstrap super admin created: {}", adminEmail);
        }
    }
}
