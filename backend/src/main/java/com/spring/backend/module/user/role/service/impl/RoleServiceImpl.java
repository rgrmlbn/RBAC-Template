package com.spring.backend.module.user.role.service.impl;

import com.spring.backend.module.exception.common.ResourceNotFoundException;

import com.spring.backend.module.exception.user.role.DuplicateRoleException;
import com.spring.backend.module.exception.user.role.RoleInUseException;
import com.spring.backend.module.exception.user.role.RoleProtectedException;
import com.spring.backend.module.security.permission.RoleNames;
import com.spring.backend.module.security.util.EscalationGuard;
import com.spring.backend.module.user.permission.entity.PermissionEntity;
import com.spring.backend.module.user.permission.repository.PermissionRepository;
import com.spring.backend.module.user.role.dto.request.CreateRoleRequest;
import com.spring.backend.module.user.role.dto.request.SetRolePermissionsRequest;
import com.spring.backend.module.user.role.dto.request.UpdateRoleRequest;
import com.spring.backend.module.user.role.dto.response.RoleResponse;
import com.spring.backend.module.user.role.entity.RoleEntity;
import com.spring.backend.module.user.role.mapper.RoleMapper;
import com.spring.backend.module.user.role.repository.RoleRepository;
import com.spring.backend.module.user.role.service.interfaces.RoleService;
import com.spring.backend.module.user.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class RoleServiceImpl implements RoleService {

    private final RoleRepository roleRepository;
    private final PermissionRepository permissionRepository;
    private final UserRepository userRepository;
    private final RoleMapper roleMapper;
    private final EscalationGuard escalationGuard;

    @Override
    @Transactional(readOnly = true)
    public List<RoleResponse> getAllRoles() {
        return roleRepository.findAll().stream().map(roleMapper::toResponse).toList();
    }

    @Override
    @Transactional(readOnly = true)
    public RoleResponse getRoleById(Long id) {
        return roleMapper.toResponse(find(id));
    }

    @Override
    @Transactional
    public RoleResponse createRole(CreateRoleRequest request) {
        String name = normalize(request.getName());
        if (roleRepository.existsByName(name)) {
            throw new DuplicateRoleException();
        }

        RoleEntity role = new RoleEntity();
        role.setName(name);
        role.setDescription(request.getDescription());

        if (request.getPermissions() != null && !request.getPermissions().isEmpty()) {
            escalationGuard.assertCanGrant(request.getPermissions());
            role.setPermissions(resolvePermissions(request.getPermissions()));
        }

        return roleMapper.toResponse(roleRepository.save(role));
    }

    @Override
    @Transactional
    public RoleResponse updateRole(Long id, UpdateRoleRequest request) {
        RoleEntity role = find(id);

        if (request.getName() != null && !request.getName().isBlank()) {
            String name = normalize(request.getName());
            if (!name.equals(role.getName())) {
                if (role.isSystemRole()) {
                    throw new RoleProtectedException();
                }
                if (roleRepository.existsByName(name)) {
                    throw new DuplicateRoleException();
                }
                role.setName(name);
            }
        }
        if (request.getDescription() != null) {
            role.setDescription(request.getDescription());
        }

        return roleMapper.toResponse(roleRepository.save(role));
    }

    @Override
    @Transactional
    public RoleResponse setPermissions(Long id, SetRolePermissionsRequest request) {
        RoleEntity role = find(id);

        // SUPER_ADMIN always holds everything; keeps the system from being locked out
        if (RoleNames.SUPER_ADMIN.equals(role.getName())) {
            throw new RoleProtectedException();
        }

        escalationGuard.assertCanGrant(request.getPermissions());
        role.setPermissions(resolvePermissions(request.getPermissions()));

        return roleMapper.toResponse(roleRepository.save(role));
    }

    @Override
    @Transactional
    public void deleteRole(Long id) {
        RoleEntity role = find(id);

        if (role.isSystemRole()) {
            throw new RoleProtectedException();
        }
        if (userRepository.existsByRolesId(id)) {
            throw new RoleInUseException();
        }

        roleRepository.delete(role);
    }

    // ---- helpers ----

    private RoleEntity find(Long id) {
        return roleRepository.findWithPermissionsById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Role"));
    }

    private Set<PermissionEntity> resolvePermissions(Set<String> names) {
        Set<PermissionEntity> found = new HashSet<>(permissionRepository.findAllByNameIn(names));
        if (found.size() != names.size()) {
            throw new ResourceNotFoundException("Permission");
        }
        return found;
    }

    private String normalize(String name) {
        return name.trim().toUpperCase().replace(' ', '_');
    }
}
