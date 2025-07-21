package com.oneaccess.auth.services.auth;

import com.oneaccess.auth.services.auth.dtos.AuthResponseDTO;
import com.oneaccess.auth.services.auth.dtos.LoginRequestDTO;
import com.oneaccess.auth.services.auth.dtos.RegisterUserRequestDTO;
import com.oneaccess.auth.services.webapp.user.dto.UserDTO;

public interface AuthenticationService {

    AuthResponseDTO loginUser(LoginRequestDTO loginRequest);

    UserDTO registerUser(RegisterUserRequestDTO registerUserRequestDTO);

}
