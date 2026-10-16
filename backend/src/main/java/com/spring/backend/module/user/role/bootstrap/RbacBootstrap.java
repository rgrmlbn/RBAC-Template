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

import javax.management.relation.Role;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;

/**
 * Initializes the application's role-based access control (RBAC) data on startup.
 *
 * <p>Ensures that all permissions declared in {@link Perm} exist in the database,
 * creates the built-in SUPER_ADMIN and USER roles when missing, and synchronizes
 * the SUPER_ADMIN role with all available permissions on every startup.
 *
 * <p>Creates the initial SUPER_ADMIN account from application configuration
 * only when no SUPER_ADMIN exists and the configured email is not already in use.
 * Repeated executions are idempotent and do not recreate existing records.
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

    /**
     * Initializes permissions, built-in roles, and the initial administrator.
     *
     * <p>Runs within a transaction so the bootstrap operations are committed
     * together or rolled back if an unchecked exception occurs.
     *
     * @param args the application arguments supplied at startup
     */
    @Override
    @Transactional
    public void run(ApplicationArguments args) {

        // → Ensure every declared permission exists in the database.
        Map<String, PermissionEntity> permissions = new HashMap<>();
        permissionRepository.findAll().forEach(p -> permissions.put(p.getName(), p));

        for (String name : Perm.all()) {
            // → Create the permission only if it does not already exist in the map.
            if (!permissions.containsKey(name)) {
                PermissionEntity permission = PermissionEntity.builder()
                        .name(name)
                        .build();

                permission = permissionRepository.save(permission);

                permissions.put(name, permission);
            }
        }

        // → Create or synchronize the built-in SUPER_ADMIN role.
        RoleEntity superAdmin = roleRepository.findByName(RoleNames.SUPER_ADMIN).orElseGet(() -> {

            RoleEntity r = RoleEntity.builder()
                    .name(RoleNames.SUPER_ADMIN)
                    .description("Full access. Cannot be modified or deleted.")
                    .systemRole(true)
                    .build();

            return r;
        });

        // → Ensure SUPER_ADMIN always has every declared permission.
        superAdmin.setPermissions(new HashSet<>(permissions.values()));
        superAdmin = roleRepository.save(superAdmin);

        // → Create the default USER role only when it does not already exist.
        roleRepository.findByName(RoleNames.USER).orElseGet(() -> {

            RoleEntity r = RoleEntity.builder()
                    .name(RoleNames.USER)
                    .description("Default role for registered users.")
                    .systemRole(true)
                    .build();

            return roleRepository.save(r);
        });

        // → Create the initial SUPER_ADMIN only with configured credentials,
        //   no existing SUPER_ADMIN, and an unused email.
        if (!adminEmail.isBlank() && !adminPassword.isBlank()
                && userRepository.countByRolesName(RoleNames.SUPER_ADMIN) == 0
                && !userRepository.existsByEmail(adminEmail)) {

            UserEntity admin = UserEntity.builder()
                    .name(adminName)
                    .email(adminEmail)
                    .password(passwordEncoder.encode(adminPassword))
                    .build();

            // → Assign the built-in SUPER_ADMIN role to the initial administrator.
            admin.getRoles().add(superAdmin);
            userRepository.save(admin);

            log.info("Bootstrap super admin created: {}", adminEmail);
        }
    }
}