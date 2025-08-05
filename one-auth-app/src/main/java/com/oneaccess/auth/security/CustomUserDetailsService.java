package com.oneaccess.auth.security;

import com.oneaccess.auth.entities.UserEntity;
import com.oneaccess.auth.repository.UserRepository;
import com.oneaccess.auth.utils.exceptions.AppExceptionConstants;
import com.oneaccess.authjar.user.CustomUserDetails;
import com.oneaccess.authjar.user.OneAuthUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Slf4j
@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(AppExceptionConstants.BAD_LOGIN_CREDENTIALS));
        OneAuthUser oneAuthUser = UserEntity.buildOneAuthUser(userEntity);
        log.info("loadUserByUsername: {}", username);
        return CustomUserDetails.buildFromUserEntity(userEntity.getEmail(), userEntity.getPassword(), oneAuthUser);
    }
}