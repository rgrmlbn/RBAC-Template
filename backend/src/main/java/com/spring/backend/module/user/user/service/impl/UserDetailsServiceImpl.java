package com.spring.backend.module.user.user.service.impl;

import com.spring.backend.module.security.principal.UserPrincipal;
import com.spring.backend.module.user.user.entity.UserEntity;
import com.spring.backend.module.user.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Loads users for Spring Security, both at login and on every authenticated request
 * (the JWT filter calls it to rebuild the principal from the token's email).
 *
 * <p>Authorities come from the database each time rather than from the token, so
 * role and permission changes take effect immediately.
 */
@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    /**
     * Loads a user by email, with their roles and permissions.
     *
     * @param email the user's email, which is the username in this application
     * @return the principal exposing the user's permissions as authorities
     * @throws UsernameNotFoundException if no user has this email
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        // → Roles and permissions must be fetched here: callers such as the JWT filter run outside a transaction, so lazy loading would fail later in getAuthorities()
        UserEntity user = userRepository.findWithRolesByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("Invalid email or password."));

        return new UserPrincipal(user);
    }
}