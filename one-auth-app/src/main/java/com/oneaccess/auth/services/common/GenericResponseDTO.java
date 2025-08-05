package com.oneaccess.auth.services.common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class GenericResponseDTO<T> {

    private T response;

    private String messageCode;
    
    private String errorId;
    
    public GenericResponseDTO(String messageCode, T response) {
        this.messageCode = messageCode;
        this.response = response;
    }
}
