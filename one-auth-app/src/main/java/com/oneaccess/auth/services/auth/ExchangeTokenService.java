package com.oneaccess.auth.services.auth;

import com.oneaccess.auth.services.auth.dtos.TokenExchangeRequestDTO;
import com.oneaccess.auth.services.auth.dtos.TokenExchangeResponseDTO;

public interface ExchangeTokenService {
    
    TokenExchangeResponseDTO exchangeCodeForToken(TokenExchangeRequestDTO request);
    
}