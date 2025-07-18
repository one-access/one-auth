package com.oneaccess.auth.springcustomizedstarterexample.services.common;

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
}
