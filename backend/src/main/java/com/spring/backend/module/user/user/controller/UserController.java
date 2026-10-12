package com.spring.backend.module.user.user.controller;

import com.spring.backend.module.security.permission.Perm;
import com.spring.backend.module.user.auth.dto.request.AssignRolesRequest;
import com.spring.backend.module.user.user.dto.request.ChangePasswordRequest;
import com.spring.backend.module.user.user.dto.request.UpdateUserRequest;
import com.spring.backend.module.user.user.dto.response.UserResponse;
import com.spring.backend.module.user.user.service.interfaces.UserService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
@Validated
public class UserController {

    // "self" = the id in the URL belongs to the logged-in user (principal is UserPrincipal)
    private static final String SELF = "#id == authentication.principal.user.id";

    private final UserService userService;

    @GetMapping
    @PreAuthorize("hasAuthority('" + Perm.USER_READ + "')")
    public ResponseEntity<List<UserResponse>> getAllUsers() {
        return ResponseEntity.ok(userService.getAllUsers());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('" + Perm.USER_READ + "') or " + SELF)
    public ResponseEntity<UserResponse> getUserById(@PathVariable @Positive Long id) {
        return ResponseEntity.ok(userService.getUserById(id));
    }

    @PatchMapping("/{id}/update")
    @PreAuthorize("hasAuthority('" + Perm.USER_UPDATE + "') or " + SELF)
    public ResponseEntity<UserResponse> updateUserById(@PathVariable @Positive Long id,
                                                       @RequestBody @Valid UpdateUserRequest update) {
        return ResponseEntity.ok(userService.updateUserById(id, update));
    }

    // Own password only: your service verifies the current password, so nobody else should call this for you
    @PatchMapping("/{id}/change-password")
    @PreAuthorize(SELF)
    public ResponseEntity<Void> changePasswordById(@PathVariable @Positive Long id,
                                                   @RequestBody @Valid ChangePasswordRequest changePassword) {
        userService.changePasswordById(id, changePassword);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('" + Perm.USER_DELETE + "')")
    public ResponseEntity<Void> deleteUserById(@PathVariable @Positive Long id) {
        userService.deleteUserById(id);
        return ResponseEntity.noContent().build();
    }

    // NEW
    @PutMapping("/{id}/roles")
    @PreAuthorize("hasAuthority('" + Perm.USER_ASSIGN_ROLE + "')")
    public ResponseEntity<UserResponse> assignRoles(@PathVariable @Positive Long id,
                                                    @RequestBody @Valid AssignRolesRequest request) {
        return ResponseEntity.ok(userService.assignRolesById(id, request));
    }
}