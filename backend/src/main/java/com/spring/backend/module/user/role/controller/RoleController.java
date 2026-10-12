package com.spring.backend.module.user.role.controller;

import com.spring.backend.module.security.permission.Perm;
import com.spring.backend.module.user.role.dto.request.CreateRoleRequest;
import com.spring.backend.module.user.role.dto.request.SetRolePermissionsRequest;
import com.spring.backend.module.user.role.dto.request.UpdateRoleRequest;
import com.spring.backend.module.user.role.dto.response.RoleResponse;
import com.spring.backend.module.user.role.service.interfaces.RoleService;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Positive;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/roles")
@RequiredArgsConstructor
@Validated
public class RoleController {

    private final RoleService roleService;

    @GetMapping
    @PreAuthorize("hasAuthority('" + Perm.ROLE_READ + "')")
    public ResponseEntity<List<RoleResponse>> getAllRoles() {
        return ResponseEntity.ok(roleService.getAllRoles());
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAuthority('" + Perm.ROLE_READ + "')")
    public ResponseEntity<RoleResponse> getRoleById(@PathVariable @Positive Long id) {
        return ResponseEntity.ok(roleService.getRoleById(id));
    }

    @PostMapping
    @PreAuthorize("hasAuthority('" + Perm.ROLE_CREATE + "')")
    public ResponseEntity<RoleResponse> createRole(@RequestBody @Valid CreateRoleRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(roleService.createRole(request));
    }

    @PatchMapping("/{id}")
    @PreAuthorize("hasAuthority('" + Perm.ROLE_UPDATE + "')")
    public ResponseEntity<RoleResponse> updateRole(@PathVariable @Positive Long id,
                                                   @RequestBody @Valid UpdateRoleRequest request) {
        return ResponseEntity.ok(roleService.updateRole(id, request));
    }

    @PutMapping("/{id}/permissions")
    @PreAuthorize("hasAuthority('" + Perm.ROLE_UPDATE + "')")
    public ResponseEntity<RoleResponse> setPermissions(@PathVariable @Positive Long id,
                                                       @RequestBody @Valid SetRolePermissionsRequest request) {
        return ResponseEntity.ok(roleService.setPermissions(id, request));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('" + Perm.ROLE_DELETE + "')")
    public ResponseEntity<Void> deleteRole(@PathVariable @Positive Long id) {
        roleService.deleteRole(id);
        return ResponseEntity.noContent().build();
    }
}
