package com.oneaccess.auth.services.webapp.user;

import com.oneaccess.auth.entities.UserEntity;
import com.oneaccess.auth.services.webapp.user.dto.UserDTO;
import org.mapstruct.Mapper;

import java.util.List;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserEntity toEntity(UserDTO dto);

    UserDTO toDto(UserEntity entity);

    List<UserEntity> toEntityList(List<UserDTO> list);

    List<UserDTO> toDtoList(List<UserEntity> list);
}