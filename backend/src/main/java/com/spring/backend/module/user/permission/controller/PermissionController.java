package com.spring.backend.module.user.permission.controller;

import com.spring.backend.module.security.permission.Perm;
import com.spring.backend.module.user.permission.dto.response.PermissionResponse;
import com.spring.backend.module.user.permission.repository.PermissionRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Comparator;
import java.util.List;

@RestController
@RequestMapping("/api/v1/permissions")
@RequiredArgsConstructor
public class PermissionController {

    private final PermissionRepository permissionRepository;

    // Lists the permissions an admin UI can pick from when building a role
    @GetMapping
    @PreAuthorize("hasAuthority('" + Perm.ROLE_READ + "')")
    public ResponseEntity<List<PermissionResponse>> getAllPermissions() {
        return ResponseEntity.ok(permissionRepository.findAll().stream()
                .map(p -> PermissionResponse.builder()
                        .id(p.getId())
                        .name(p.getName())
                        .build())
                .sorted(Comparator.comparing(permissionResponse -> permissionResponse.getName()))
                .toList());
    }
}
