package com.oneaccess.auth.springcustomizedstarterexample.services.webapp.user;

import com.oneaccess.auth.springcustomizedstarterexample.entities.UserEntity;
import com.oneaccess.auth.springcustomizedstarterexample.services.common.GenericMapper;
import com.oneaccess.auth.springcustomizedstarterexample.services.webapp.user.dto.UserDTO;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper extends GenericMapper<UserDTO, UserEntity> {

    @Override
    UserEntity toEntity(UserDTO dto);

    @Override
    UserDTO toDto(UserEntity entity);

    @Override
    List<UserEntity> toEntityList(List<UserDTO> list);

    @Override
    List<UserDTO> toDtoList(List<UserEntity> list);

}