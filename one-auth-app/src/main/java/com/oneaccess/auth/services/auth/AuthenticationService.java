package com.oneaccess.auth.springcustomizedstarterexample.services.auth;

import com.oneaccess.auth.springcustomizedstarterexample.services.auth.dtos.AuthResponseDTO;
import com.oneaccess.auth.springcustomizedstarterexample.services.auth.dtos.LoginRequestDTO;
import com.oneaccess.auth.springcustomizedstarterexample.services.auth.dtos.RegisterUserRequestDTO;
import com.oneaccess.auth.springcustomizedstarterexample.services.webapp.user.dto.UserDTO;

public interface AuthenticationService {

    AuthResponseDTO loginUser(LoginRequestDTO loginRequest);

    UserDTO registerUser(RegisterUserRequestDTO registerUserRequestDTO);

}
