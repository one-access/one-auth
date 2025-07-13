package com.oneaccess.auth.springcustomizedstarterexample.services.auth;

import com.oneaccess.auth.springcustomizedstarterexample.security.JWTTokenProvider;
import com.oneaccess.auth.springcustomizedstarterexample.security.oauth.common.SecurityEnums;
import com.oneaccess.auth.springcustomizedstarterexample.services.auth.dtos.AuthResponseDTO;
import com.oneaccess.auth.springcustomizedstarterexample.services.auth.dtos.LoginRequestDTO;
import com.oneaccess.auth.springcustomizedstarterexample.services.auth.dtos.RegisterUserRequestDTO;
import com.oneaccess.auth.springcustomizedstarterexample.services.webapp.user.UserService;
import com.oneaccess.auth.springcustomizedstarterexample.services.webapp.user.dto.UserDTO;
import com.oneaccess.auth.springcustomizedstarterexample.utils.exceptions.AppExceptionConstants;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationServiceImpl implements AuthenticationService {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final JWTTokenProvider jwtTokenProvider;

    public AuthenticationServiceImpl(AuthenticationManager authenticationManager,
                                     UserService userService,
                                     JWTTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }


    @Override
    public AuthResponseDTO loginUser(LoginRequestDTO loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            String token = jwtTokenProvider.createJWTToken(authentication);
            AuthResponseDTO authResponseDTO = new AuthResponseDTO();
            authResponseDTO.setToken(token);
            return authResponseDTO;
        } catch (AuthenticationException e) {
            if (e instanceof DisabledException) {
                throw new BadCredentialsException(AppExceptionConstants.ACCOUNT_NOT_ACTIVATED);
            }
            throw new BadCredentialsException(e.getMessage());
        }
    }

    @Override
    public UserDTO registerUser(RegisterUserRequestDTO registerUserRequestDTO) {
        UserDTO userDTO = new UserDTO();
        userDTO.setEmail(registerUserRequestDTO.getEmail());
        userDTO.setPassword(registerUserRequestDTO.getPassword());
        userDTO.setFullName(registerUserRequestDTO.getFullName());
        userDTO.setRegisteredProviderName(SecurityEnums.AuthProviderId.app_custom_authentication);
        UserDTO user = userService.createUser(userDTO);
        return user;
    }

}
