package com.spring.backend.module.user.user.service.interfaces;



import com.spring.backend.module.user.auth.dto.request.AssignRolesRequest;
import com.spring.backend.module.user.user.dto.request.ChangePasswordRequest;
import com.spring.backend.module.user.user.dto.request.UpdateUserRequest;
import com.spring.backend.module.user.user.dto.response.UserResponse;

import java.util.List;

public interface UserService {

    // ADMIN ENDPOINTS

    List<UserResponse> getAllUsers();

    UserResponse getUserById(Long id);

    UserResponse updateUserById(Long id, UpdateUserRequest update);

    void changePasswordById(Long id, ChangePasswordRequest request);

    void deleteUserById(Long id);

    UserResponse assignRolesById(Long id, AssignRolesRequest request);

    // USERS ENDPOINT

    UserResponse getMe();

    UserResponse updateMe(UpdateUserRequest update);

    void changeMyPassword(ChangePasswordRequest request);

    void deleteMyAccount(Long id);

}