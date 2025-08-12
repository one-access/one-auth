package com.oneaccess.auth.services.auth;

import com.oneaccess.auth.services.auth.dtos.LoginRequestDTO;
import com.oneaccess.auth.services.auth.dtos.RegisterUserRequestDTO;
import com.oneaccess.auth.services.auth.dtos.TokenResponseDTO;
import com.oneaccess.auth.services.webapp.user.dto.UserDTO;

public interface AuthenticationService {

    TokenResponseDTO loginUser(LoginRequestDTO loginRequest);

    UserDTO registerUser(RegisterUserRequestDTO registerUserRequestDTO);

}
