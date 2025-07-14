package com.oneaccess.auth.services.webapp.user.dto;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UpdatePasswordRequestDTO {

    @NotNull(message = "Current password cannot be null")
    private String currentPassword;

    @NotNull(message = "New password cannot be null")
    private String newPassword;

    @NotNull(message = "Confirm password cannot be null")
    private String confirmPassword;
}
