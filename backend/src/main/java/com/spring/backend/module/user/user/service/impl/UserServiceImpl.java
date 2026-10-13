
package com.spring.backend.module.user.user.service.impl;

import com.spring.backend.module.exception.common.ResourceNotFoundException;
import com.spring.backend.module.exception.user.role.LastSuperAdminException;
import com.spring.backend.module.exception.user.user.DuplicateEmailException;
import com.spring.backend.module.exception.user.user.IncorrectCurrentPasswordException;
import com.spring.backend.module.exception.user.user.PasswordMismatchException;
import com.spring.backend.module.exception.user.user.PasswordReuseException;
import com.spring.backend.module.security.permission.RoleNames;
import com.spring.backend.module.security.util.CurrentUser;
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
import org.springframework.security.access.AccessDeniedException;

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

    // ADMIN ENDPOINTS

    // Desc: Get all users
    @Override
    @Transactional(readOnly = true)
    public List<UserResponse> getAllUsers() {

        return userRepository.findAll().stream()
                .map(userMapper::toResponse)
                .toList();
    }

    // Desc: Get a user by its ID, throwing an exception if not found
    @Override
    @Transactional(readOnly = true)
    public UserResponse getUserById(Long id) {

        UserEntity user = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        return userMapper.toResponse(user);
    }

    // Desc: Update a user by its ID (ownership / permission is enforced by @PreAuthorize on the controller)
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

    // Desc: Change a user's password by ID, validating the current password
    // Note: All refresh tokens are deleted after the password change, requiring the user to authenticate again
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

    // Desc: Delete a user by its ID
    // Note: Cannot delete the last SUPER_ADMIN
    @Override
    @Transactional
    public void deleteUserById(Long id) {

        UserEntity user = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        if (isSuperAdmin(user) && userRepository.countByRolesName(RoleNames.SUPER_ADMIN) <= 1) {
            throw new LastSuperAdminException();
        }

        // Delete refresh tokens to prevent further token renewal
        // Access tokens are not stored in the database and will expire naturally
        refreshTokenService.deleteAllByUser(user);
        userRepository.delete(user);
    }

    // Desc: Replace the roles assigned to a user by their ID
    // Note: The caller can only grant permissions they already possess
    // Note: Cannot remove the last SUPER_ADMIN from the system
    @Override
    @Transactional
    public UserResponse assignRolesById(Long id, AssignRolesRequest request) {

        UserEntity user = userRepository.findWithRolesById(id)
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        Set<Long> requestedIds = request.getRoleIds();
        List<RoleEntity> roles = roleRepository.findAllById(requestedIds);

        // Ensure that every requested role exists
        if (roles.size() != requestedIds.size()) {
            throw new ResourceNotFoundException("Role");
        }

        // Anti-escalation: caller can only grant roles whose permissions they already hold.
        // Role permissions are loaded inside the transaction because the relationship is LAZY.
        Set<String> toGrant = roles.stream()
                .flatMap(r -> r.getPermissions().stream())
                .map(permissionEntity -> permissionEntity.getName())
                .collect(Collectors.toSet());

        escalationGuard.assertCanGrant(toGrant);

        // Prevent the system from losing its last SUPER_ADMIN
        boolean losesSuperAdmin = isSuperAdmin(user)
                && roles.stream().noneMatch(r -> RoleNames.SUPER_ADMIN.equals(r.getName()));

        if (losesSuperAdmin && userRepository.countByRolesName(RoleNames.SUPER_ADMIN) <= 1) {
            throw new LastSuperAdminException();
        }

        // Replace the user's existing roles with the requested roles
        user.setRoles(new HashSet<>(roles));

        return userMapper.toResponse(userRepository.save(user));
    }

    // Desc: Check whether a user has the SUPER_ADMIN role
    // Note: Used to protect the system from losing its last SUPER_ADMIN
    private boolean isSuperAdmin(UserEntity user) {
        return user.getRoles().stream()
                .anyMatch(r -> RoleNames.SUPER_ADMIN.equals(r.getName()));
    }

    // USER ENDPOINTS

    // Desc: Get the currently authenticated user's information, including their roles
    @Transactional(readOnly = true)
    public UserResponse getMe() {

        UserEntity me = userRepository.findWithRolesById(CurrentUser.id())
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        return userMapper.toResponse(me);
    }

    // Desc: Update the currently authenticated user's information
    @Transactional
    public UserResponse updateMe(UpdateUserRequest update) {

        UserEntity me = userRepository.findWithRolesById(CurrentUser.id())
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        // Update fields if they are not null or blank
        if (update.getName() != null && !update.getName().isBlank()) {
            me.setName(update.getName());
        }

        // Update email if it is not null or blank, checking for duplicate emails
        if (update.getEmail() != null && !update.getEmail().isBlank()) {
            if (!me.getEmail().equals(update.getEmail()) &&
                    userRepository.existsByEmail(update.getEmail())) {
                throw new DuplicateEmailException();
            }
            me.setEmail(update.getEmail());
        }

        UserEntity updatedMe = userRepository.save(me);

        return userMapper.toResponse(updatedMe);
    }

    // Desc: Change the currently authenticated user's password, validating the current password
    // Note: All refresh tokens are deleted after the password change, requiring the user to authenticate again
    @Transactional
    public void changeMyPassword(ChangePasswordRequest request) {

        UserEntity me = userRepository.findWithRolesById(CurrentUser.id())
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        if (!passwordEncoder.matches(request.getCurrentPassword(), me.getPassword())) {
            throw new IncorrectCurrentPasswordException();
        }

        if (!request.getNewPassword().equals(request.getConfirmPassword())) {
            throw new PasswordMismatchException();
        }

        if (passwordEncoder.matches(request.getNewPassword(), me.getPassword())) {
            throw new PasswordReuseException();
        }

        me.setPassword(passwordEncoder.encode(request.getNewPassword()));

        refreshTokenService.deleteAllByUser(me);

        userRepository.save(me);
    }

    // Desc: Delete the currently authenticated user's account
    // Note: The provided ID must match the authenticated user's ID
    // Note: Cannot delete the last SUPER_ADMIN
    @Transactional
    public void deleteMyAccount(Long id) {

        UserEntity me = userRepository.findWithRolesById(CurrentUser.id())
                .orElseThrow(() -> new ResourceNotFoundException("User"));

        // Prevent the user from deleting another user's account
        if (!me.getId().equals(id)) {
            throw new AccessDeniedException("Cannot delete another user's account");
        }

        // Prevent the system from losing its last SUPER_ADMIN
        if (isSuperAdmin(me) && userRepository.countByRolesName(RoleNames.SUPER_ADMIN) <= 1) {
            throw new LastSuperAdminException();
        }

        // Delete refresh tokens to prevent further token renewal
        // Access tokens are not stored in the database and will expire naturally
        refreshTokenService.deleteAllByUser(me);
        userRepository.delete(me);
    }
}
