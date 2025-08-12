package com.oneaccess.auth.services.webapp.user;

import com.oneaccess.auth.config.AppProperties;
import com.oneaccess.auth.entities.UserEntity;
import com.oneaccess.auth.repository.UserRepository;
import com.oneaccess.authjar.utils.AppUserUtil;
import com.oneaccess.authjar.user.enums.ProviderEnums;
import com.oneaccess.auth.services.common.GenericResponseDTO;
import com.oneaccess.auth.services.mail.DispatcherEmailService;
import com.oneaccess.auth.services.webapp.user.dto.*;
import com.oneaccess.auth.utils.AppUtils;
import com.oneaccess.auth.utils.exceptions.AppExceptionConstants;
import com.oneaccess.auth.utils.exceptions.BadRequestException;
import com.oneaccess.auth.utils.exceptions.CustomAppException;
import com.oneaccess.auth.utils.exceptions.ResourceNotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.ObjectUtils;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@Transactional
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserMapper userMapper;
    private final DispatcherEmailService emailService;
    private final AppProperties appProperties;

    public UserServiceImpl(UserRepository userRepository,
                           PasswordEncoder passwordEncoder,
                           UserMapper userMapper,
                           DispatcherEmailService emailService,
                           AppProperties appProperties) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.userMapper = userMapper;
        this.emailService = emailService;
        this.appProperties = appProperties;
    }


    @Override
    public List<UserDTO> getAllUsers(Pageable pageable) {
        Page<UserEntity> pageUserEntities = userRepository.findAll(pageable);
        return userMapper.toDtoList(pageUserEntities.getContent());
    }

    @Override
    public UserDTO findUserByEmail(String userEmail) {
        UserEntity userEntity = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.USER_RECORD_NOT_FOUND));
        return userMapper.toDto(userEntity);
    }

    @Override
    public Optional<UserDTO> findOptionalUserByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(userEntity -> userMapper.toDto(userEntity));
    }

    @Override
    public UserDTO getUserById(Long id) {
        UserEntity userEntity = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.USER_RECORD_NOT_FOUND));
        return userMapper.toDto(userEntity);
    }

    @Override
//    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public UserDTO createUser(UserDTO requestUserDTO) {
        if (ObjectUtils.isEmpty(requestUserDTO.getRoles())) {
            requestUserDTO.setRoles(Set.of(AppUserUtil.ROLE_DEFAULT));
        }
        boolean isFromCustomBasicAuth = ProviderEnums.AuthProviderId.app_custom_authentication
                .equals(requestUserDTO.getRegisteredProviderName());
        if (isFromCustomBasicAuth && requestUserDTO.getPassword() != null) {
            requestUserDTO.setPassword(passwordEncoder.encode(requestUserDTO.getPassword()));
        }
        UserEntity userEntity = userMapper.toEntity(requestUserDTO);
        boolean existsByEmail = userRepository.existsByEmail(userEntity.getEmail());
        if (existsByEmail) {
            throw new ResourceNotFoundException(AppExceptionConstants.USER_EMAIL_NOT_AVAILABLE);
        }
        boolean shouldSendVerificationEmailForSignup = isFromCustomBasicAuth && appProperties.getAuth().getEmail().isVerRequiredForCustomSignup();

        // Dev mode is enabled.
        if(appProperties.getDevConfig().isEnabled() && appProperties.getDevConfig().isDisabledEmailSend()) {
            userEntity.setEmailVerified(true);
            userRepository.save(userEntity);
            return userMapper.toDto(userEntity);
        }

        // Auto-verify if verification via social sign on or if the verificationRequired is disabled
        if (!shouldSendVerificationEmailForSignup) {
            userEntity.setEmailVerified(true);  // Auto-verify if verification not required
        }

        userRepository.save(userEntity);
        
        // Send verification email if e customAuth only if email is enabled
        if (shouldSendVerificationEmailForSignup) {
            sendVerificationEmail(userEntity.getEmail());
        }
        
        return userMapper.toDto(userEntity);
    }

    @Override
    public UserDTO updateUser(UserDTO reqUserDTO) {
        UserEntity userEntity = userRepository.findById(reqUserDTO.getId())
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.USER_RECORD_NOT_FOUND));
        userEntity.setFullName(reqUserDTO.getFullName());
        // userEntity.setDisplayName(reqUserDTO.getDisplayName())
        userRepository.save(userEntity);
        return userMapper.toDto(userEntity);
    }

    @Override
//    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public GenericResponseDTO<Boolean> sendVerificationEmail(String email) {
        UserEntity userEntity = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.USER_RECORD_NOT_FOUND));
        String verificationCode = AppUtils.generateRandomAlphaNumericString(20);
        long verificationCodeExpirationSeconds = appProperties.getMail().getVerificationCodeExpirationDuration().getSeconds();
        userEntity.setVerificationCodeExpiresAt(Instant.now().plusSeconds(verificationCodeExpirationSeconds));
        userEntity.setVerificationCode(verificationCode);
        userRepository.save(userEntity);
        emailService.sendVerificationEmail(userEntity.getEmail());
        GenericResponseDTO<Boolean> genericResponseDTO = GenericResponseDTO.<Boolean>builder().response(true).build();
        return genericResponseDTO;
    }

    @Override
    public GenericResponseDTO<Boolean> sendResetPasswordEmail(ForgotPasswordRequestDTO forgotPasswordRequestDTO) {
        UserEntity userEntity = userRepository.findByEmail(forgotPasswordRequestDTO.getEmail())
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.USER_EMAIL_NOT_AVAILABLE));
        String forgotPasswordVerCode = AppUtils.generateRandomAlphaNumericString(20);
        long verificationCodeExpirationSeconds = appProperties.getMail().getVerificationCodeExpirationDuration().getSeconds();
        userEntity.setVerificationCodeExpiresAt(Instant.now().plusSeconds(verificationCodeExpirationSeconds));
        userEntity.setVerificationCode(forgotPasswordVerCode);
        userRepository.save(userEntity);
        emailService.sendPasswordResetEmail(userEntity.getEmail());
        GenericResponseDTO<Boolean> genericResponseDTO = GenericResponseDTO.<Boolean>builder().response(true).build();
        return genericResponseDTO;
    }

    @Override
    public GenericResponseDTO<Boolean> verifyEmailAddress(VerifyEmailRequestDTO verifyEmailRequestDTO) {
        Optional<UserEntity> optionalUserEntity = userRepository.verifyAndRetrieveEmailVerificationRequestUser(
                verifyEmailRequestDTO.getEmail(), verifyEmailRequestDTO.getAuthProviderId(), verifyEmailRequestDTO.getVerificationCode());
        UserEntity userEntity = optionalUserEntity
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.MATCHING_VERIFICATION_RECORD_NOT_FOUND));
        userEntity.setEmailVerified(Boolean.TRUE);
        userEntity.setVerificationCodeExpiresAt(null);
        userEntity.setVerificationCode(null);
        userRepository.save(userEntity);
        emailService.sendWelcomeEmail(userEntity.getEmail(), userEntity.getFullName());
        GenericResponseDTO<Boolean> emailVerifiedResponseDTO = GenericResponseDTO.<Boolean>builder().response(true).build();
        return emailVerifiedResponseDTO;
    }

    @Override
    public GenericResponseDTO<Boolean> verifyAndProcessPasswordResetRequest(ResetPasswordRequestDTO resetPasswordRequestDTO) {
        Optional<UserEntity> optionalUserEntity = userRepository.verifyAndRetrieveForgotPasswordRequestUser(
                resetPasswordRequestDTO.getEmail(), ProviderEnums.AuthProviderId.app_custom_authentication, resetPasswordRequestDTO.getForgotPasswordVerCode());
        UserEntity userEntity = optionalUserEntity
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.INVALID_PASSWORD_RESET_REQUEST));
        userEntity.setVerificationCodeExpiresAt(null);
        userEntity.setVerificationCode(null);
        userEntity.setEmailVerified(true);
        userEntity.setPassword(passwordEncoder.encode(resetPasswordRequestDTO.getNewPassword()));
        userRepository.save(userEntity);
        GenericResponseDTO<Boolean> emailVerifiedResponseDTO = GenericResponseDTO.<Boolean>builder().response(true).build();
        return emailVerifiedResponseDTO;
    }

    @Override
    public GenericResponseDTO<Boolean> userEmailExists(String email) {
        boolean existsByEmail = userRepository.existsByEmail(email);
        return GenericResponseDTO.<Boolean>builder().response(existsByEmail).build();
    }

    @Override
    public GenericResponseDTO<Boolean> updatePassword(UpdatePasswordRequestDTO updatePasswordRequest) {
        Long currentUserId = AppUserUtil.getCurrentUserId()
            .orElseThrow(() -> new CustomAppException(AppExceptionConstants.UNAUTHORIZED_ACCESS));
        UserEntity userEntity = userRepository.findById(currentUserId)
                .orElseThrow(() -> new ResourceNotFoundException(AppExceptionConstants.USER_RECORD_NOT_FOUND));
        boolean passwordMatches = passwordEncoder.matches(updatePasswordRequest.getCurrentPassword(), userEntity.getPassword());
        if (!passwordMatches) {
            throw new BadRequestException(AppExceptionConstants.OLD_PASSWORD_DOESNT_MATCH);
        }
        userEntity.setPassword(passwordEncoder.encode(updatePasswordRequest.getNewPassword()));
        userRepository.save(userEntity);
        return GenericResponseDTO.<Boolean>builder().response(true).build();
    }

    private static MultiValueMap<String, String> constructEmailVerificationLinkQueryParams(String email,
                                                                                           String verificationCode,
                                                                                           ProviderEnums.AuthProviderId authProvider) {
        MultiValueMap<String, String> appendQueryParams = new LinkedMultiValueMap<>();
        // Generated QueryParams for the verification link, must sync with VerifyEmailRequestDTO
        appendQueryParams.add("email", email);
        appendQueryParams.add("registeredProviderName", authProvider.toString());
        appendQueryParams.add("verificationCode", verificationCode);
        return appendQueryParams;
    }

    private static MultiValueMap<String, String> constructPasswordResetLinkQueryParams(String email,
                                                                                       String forgotPasswordVerCode) {
        MultiValueMap<String, String> appendQueryParams = new LinkedMultiValueMap<>();
        // Generated QueryParams for the password reset link, must sync with ResetPasswordRequestDTO
        appendQueryParams.add("email", email);
        appendQueryParams.add("forgotPasswordVerCode", forgotPasswordVerCode);
        return appendQueryParams;
    }

}
