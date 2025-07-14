package com.oneaccess.auth.services.auth.dtos;

import lombok.Data;

@Data
public class LoginRequestDTO {

    private String email;

    private String password;

}
