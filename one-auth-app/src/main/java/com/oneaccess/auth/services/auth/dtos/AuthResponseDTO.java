package com.oneaccess.auth.services.auth.dtos;

import com.oneaccess.authjar.user.OneAuthUser;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponseDTO {

    private String accessToken;

    private String refreshToken;

    private OneAuthUser oneAuthUser;

}
