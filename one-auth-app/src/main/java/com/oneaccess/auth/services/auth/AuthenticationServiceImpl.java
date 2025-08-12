package com.oneaccess.auth.services.auth;

import com.oneaccess.auth.security.UserJWTKeyProvider;
import com.oneaccess.auth.services.auth.dtos.TokenResponseDTO;
import com.oneaccess.authjar.user.CustomUserDetails;
import com.oneaccess.authjar.user.enums.ProviderEnums;
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

import java.time.Duration;
import java.time.LocalDateTime;

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
    public TokenResponseDTO loginUser(LoginRequestDTO loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
            CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();
            String accessToken = userJWTKeyProvider.createUserToken(customUserDetails);
            Duration jwtExpirationDuration = userJWTKeyProvider.getJwtExpirationDuration();
            TokenResponseDTO tokenResponseDTO = TokenResponseDTO.builder()
                    .tokenType("Bearer")
                    .expiresIn(jwtExpirationDuration.toSeconds())
                    .token(accessToken)
                    .refreshToken(null)
                    .authUser(customUserDetails.getOneAuthUser())
                    .tokenExpiryDate(LocalDateTime.now().plus(jwtExpirationDuration))
                    .build();

            return tokenResponseDTO;
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
