package com.oneaccess.auth.services.auth;

import com.oneaccess.auth.security.UserJWTKeyProvider;
import com.oneaccess.authjar.service.OneAuthJwtService;
import com.oneaccess.authjar.user.CustomUserDetails;
import com.oneaccess.authjar.user.enums.ProviderEnums;
import com.oneaccess.auth.services.auth.dtos.AuthResponseDTO;
import com.oneaccess.auth.services.auth.dtos.LoginRequestDTO;
import com.oneaccess.auth.services.auth.dtos.RegisterUserRequestDTO;
import com.oneaccess.auth.services.webapp.user.UserService;
import com.oneaccess.auth.services.webapp.user.dto.UserDTO;
import com.oneaccess.auth.utils.exceptions.AppExceptionConstants;
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
    private final UserJWTKeyProvider userJWTKeyProvider;

    public AuthenticationServiceImpl(AuthenticationManager authenticationManager,
                                     UserService userService,
                                     UserJWTKeyProvider userJWTKeyProvider) {
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.userJWTKeyProvider = userJWTKeyProvider;
    }


    @Override
    public AuthResponseDTO loginUser(LoginRequestDTO loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
            String token = userJWTKeyProvider.createUserToken(customUserDetails);
            AuthResponseDTO authResponseDTO = new AuthResponseDTO();
            authResponseDTO.setAccessToken(token);
            authResponseDTO.setOneAuthUser(customUserDetails.getOneAuthUser());
            authResponseDTO.setRefreshToken("refreshToken-value-to-be-supported");
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
        userDTO.setRegisteredProviderName(ProviderEnums.AuthProviderId.app_custom_authentication);
        UserDTO user = userService.createUser(userDTO);
        return user;
    }

}
