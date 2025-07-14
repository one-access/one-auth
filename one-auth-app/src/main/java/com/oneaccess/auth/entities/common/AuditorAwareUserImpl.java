package com.oneaccess.auth.entities.common;

import com.oneaccess.auth.entities.UserEntity;
import com.oneaccess.auth.repository.UserRepository;
import com.oneaccess.auth.security.AppSecurityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.AuditorAware;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component("auditorAwareUserImpl")
public class AuditorAwareUserImpl implements AuditorAware<UserEntity> {

    @Autowired
    private UserRepository userRepository;

    @Override
    public Optional<UserEntity> getCurrentAuditor() {
        Optional<Long> optionalUserId = Optional
                .ofNullable(AppSecurityUtils.getCurrentUserPrinciple())
                .map(e -> e.getUserEntity().getId());
        Optional<UserEntity> userEntity = optionalUserId.map(userId -> userRepository.getById(userId));
        return userEntity;
    }

}