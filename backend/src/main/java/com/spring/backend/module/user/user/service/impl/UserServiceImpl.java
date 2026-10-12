package com.spring.backend.module.user.user.service.impl;

import com.spring.backend.module.exception.common.ResourceNotFoundException;
import com.spring.backend.module.exception.user.role.LastSuperAdminException;
import com.spring.backend.module.exception.user.user.DuplicateEmailException;
import com.spring.backend.module.exception.user.user.IncorrectCurrentPasswordException;
import com.spring.backend.module.exception.user.user.PasswordMismatchException;
import com.spring.backend.module.exception.user.user.PasswordReuseException;
import com.spring.backend.module.security.permission.RoleNames;
import com.spring.backend.module.security.util.EscalationGuard;
import com.spring.backend.module.user.auth.dto.request.AssignRolesRequest;
import com.spring.backend.module.user.role.entity.RoleEntity;
import com.spring.backend.module.user.role.repository.RoleRepository;
import com.spring.backend.module.user.token.service.interfaces.RefreshTokenService;
import com.spring.backend.module.user.user.dto.request.ChangePasswordRequest;
import com.spring.backend.module.user.user.dto.request.UpdateUserRequest;
import com.spring.backend.module.user.user.dto.response.UserResponse;
import com.spring.backend.module.user.user.entity.UserEntity;
import com.spring.backend.module.user.user.mapper.UserMapper;
import com.spring.backend.module.user.user.repository.UserRepository;
import com.spring.backend.module.user.user.service.interfaces.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final UserMapper userMapper;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final EscalationGuard escalationGuard;

    // Get all users (CHANGED: transactional so lazy roles can be read by the mapper)
    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {

        return userRepository.findAll().stream()
                .map(userMapper::toResponse)
                .toList();
    }

    // Get a user by its ID, throwing an exception if not found
    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(Long id) {

        UserEntity user = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        return userMapper.toResponse(user);
    }

    // Update a user by its ID (ownership / permission is enforced by @PreAuthorize on the controller)
    @Override
    @Transactional
    public UserResponse updateUserById(Long id, UpdateUserRequest update) {

        UserEntity user = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        // Update fields if they are not null or blank
        if (update.getName() != null && !update.getName().isBlank()) {
            user.setName(update.getName());
        }

        // Update email if it is not null or blank, checking for duplicate emails
        if (update.getEmail() != null && !update.getEmail().isBlank()) {
            if (!user.getEmail().equals(update.getEmail()) &&
                    userRepository.existsByEmail(update.getEmail())) {
                throw new DuplicateEmailException();
            }
            user.setEmail(update.getEmail());
        }

        UserEntity updatedUser = userRepository.save(user);

        return userMapper.toResponse(updatedUser);
    }

    // Change a user's password by ID, validating the current password
    @Override
    @Transactional
    public void changePasswordById(Long id, ChangePasswordRequest request) {

        UserEntity user = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IncorrectCurrentPasswordException();
        }

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException();
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new PasswordReuseException();
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));

        refreshTokenService.deleteAllByUser(user);

        userRepository.save(user);
    }

    // Delete a user by its ID (CHANGED: cannot delete the last SUPER_ADMIN)
    @Override
    @Transactional
    public void deleteUserById(Long id) {

        UserEntity user = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        if (isSuperAdmin(user) && userRepository.countByRolesName(RoleNames.SUPER_ADMIN) <= 1) {
            throw new LastSuperAdminException();
        }

        refreshTokenService.deleteAllByUser(user); // Only delete refresh token, access token is not stored in DB and will be expired without refresh token
        userRepository.delete(user);
    }

    // NEW: replace the roles of a user
    @Override
    @Transactional
    public UserResponse assignRolesById(Long id, AssignRolesRequest request) {

        UserEntity user = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        Set<Long> requestedIds = request.getRoleIds();
        List<RoleEntity> roles = roleRepository.findAllById(requestedIds);
        if (roles.size() != requestedIds.size()) {
            throw new ResourceNotFoundException("Role");
        }

        // Anti-escalation: caller can only hand out roles whose permissions they already hold.
        // (Needs the roles' permissions loaded; they are LAZY, we are inside a transaction.)
        Set<String> toGrant = roles.stream()
                .flatMap(r -> r.getPermissions().stream())
                .map(p -> p.getName())
                .collect(Collectors.toSet());
        escalationGuard.assertCanGrant(toGrant);

        // Never leave the system without a SUPER_ADMIN
        boolean losesSuperAdmin = isSuperAdmin(user)
                && roles.stream().noneMatch(r -> RoleNames.SUPER_ADMIN.equals(r.getName()));
        if (losesSuperAdmin && userRepository.countByRolesName(RoleNames.SUPER_ADMIN) <= 1) {
            throw new LastSuperAdminException();
        }

        user.setRoles(new HashSet<>(roles));

        return userMapper.toResponse(userRepository.save(user));
    }

    private boolean isSuperAdmin(UserEntity user) {
        return user.getRoles().stream().anyMatch(r -> RoleNames.SUPER_ADMIN.equals(r.getName()));
    }
}