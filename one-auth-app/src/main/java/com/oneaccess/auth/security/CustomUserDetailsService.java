package com.oneaccess.auth.springcustomizedstarterexample.security;

import com.oneaccess.auth.springcustomizedstarterexample.entities.UserEntity;
import com.oneaccess.auth.springcustomizedstarterexample.repository.UserRepository;
import com.oneaccess.auth.springcustomizedstarterexample.utils.exceptions.AppExceptionConstants;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(AppExceptionConstants.BAD_LOGIN_CREDENTIALS));
        return CustomUserDetails.buildFromUserEntity(userEntity);
    }
}