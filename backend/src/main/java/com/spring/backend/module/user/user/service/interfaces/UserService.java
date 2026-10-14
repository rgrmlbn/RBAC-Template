package com.spring.backend.module.user.user.service.interfaces;

import com.spring.backend.module.user.auth.dto.request.AssignRolesRequest;
import com.spring.backend.module.user.user.dto.request.ChangePasswordRequest;
import com.spring.backend.module.user.user.dto.request.UpdateUserRequest;
import com.spring.backend.module.user.user.dto.response.UserResponse;

import java.util.List;

/**
 * Business operations for user accounts.
 *
 * <p>Methods ending in {@code ById} act on any user and are expected to be protected
 * by a permission check at the controller. The "me" methods act on the authenticated
 * user and take their identity from the security context.
 */
public interface UserService {

    /**
     * Returns every user with their roles.
     */
    List<UserResponse> getAllUsers();

    /**
     * Returns a single user with their roles.
     *
     * @throws com.spring.backend.module.exception.common.ResourceNotFoundException if the user does not exist
     */
    UserResponse getUserById(Long id);

    /**
     * Updates a user's name and/or email. Null or blank fields are left unchanged.
     *
     * @throws com.spring.backend.module.exception.common.ResourceNotFoundException if the user does not exist
     * @throws com.spring.backend.module.exception.user.user.DuplicateEmailException if the email is taken
     */
    UserResponse updateUserById(Long id, UpdateUserRequest update);

    /**
     * Changes a user's password after verifying the current one, then revokes all of
     * their refresh tokens so every device must log in again.
     *
     * @throws com.spring.backend.module.exception.user.user.IncorrectCurrentPasswordException if the current password is wrong
     * @throws com.spring.backend.module.exception.user.user.PasswordMismatchException if the confirmation differs
     * @throws com.spring.backend.module.exception.user.user.PasswordReuseException if the new password equals the old one
     */
    void changePasswordById(Long id, ChangePasswordRequest request);

    /**
     * Deletes a user and revokes their refresh tokens.
     *
     * @throws com.spring.backend.module.exception.user.role.LastSuperAdminException if the user is the last SUPER_ADMIN
     */
    void deleteUserById(Long id);

    /**
     * Replaces the roles assigned to a user.
     *
     * <p>The caller can only grant roles whose permissions they already hold, and the
     * last SUPER_ADMIN cannot lose that role.
     *
     * @throws com.spring.backend.module.exception.common.ResourceNotFoundException if the user or any role does not exist
     * @throws com.spring.backend.module.exception.user.role.LastSuperAdminException if it would remove the last SUPER_ADMIN
     * @throws org.springframework.security.access.AccessDeniedException if it would escalate the caller's privileges
     */
    UserResponse assignRolesById(Long id, AssignRolesRequest request);

    /**
     * Returns the authenticated user's profile.
     */
    UserResponse getMe();

    /**
     * Updates the authenticated user's name and/or email.
     *
     * @see #updateUserById(Long, UpdateUserRequest)
     */
    UserResponse updateMe(UpdateUserRequest update);

    /**
     * Changes the authenticated user's password.
     *
     * @see #changePasswordById(Long, ChangePasswordRequest)
     */
    void changeMyPassword(ChangePasswordRequest request);

    /**
     * Deletes the authenticated user's own account.
     *
     * @param id must equal the authenticated user's id
     * @throws org.springframework.security.access.AccessDeniedException if the id belongs to another user
     * @throws com.spring.backend.module.exception.user.role.LastSuperAdminException if the caller is the last SUPER_ADMIN
     */
    void deleteMyAccount(Long id);
}