package com.oneaccess.auth.services.dispatcher;

import com.oneaccess.auth.services.dispatcher.dto.DispatcherEmailRequest;
import com.oneaccess.auth.services.dispatcher.dto.DispatcherEmailResponse;
import com.oneaccess.authjar.service.OneAuthJwtService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
public class DispatcherClient {
    
    private final RestTemplate restTemplate;
    private final OneAuthJwtService oneAuthJwtService;
    private final String dispatcherBaseUrl;
    
    public DispatcherClient(RestTemplate restTemplate,
                            OneAuthJwtService oneAuthJwtService,
                           @Value("${apps.dispatcher-service.base-url}") String dispatcherBaseUrl) {
        this.restTemplate = restTemplate;
        this.oneAuthJwtService = oneAuthJwtService;
        this.dispatcherBaseUrl = dispatcherBaseUrl;
    }
    
    public DispatcherEmailResponse sendEmail(DispatcherEmailRequest request) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            
            // Add service-to-service JWT token if configured
            String serviceToken = oneAuthJwtService.createServiceToken();
            if (serviceToken != null) {
                headers.set("X-App-Auth", serviceToken);
            }
            
            HttpEntity<DispatcherEmailRequest> entity = new HttpEntity<>(request, headers);
            
            ResponseEntity<DispatcherEmailResponse> response = restTemplate.postForEntity(
                dispatcherBaseUrl + "/api/v1/emails/send",
                entity,
                DispatcherEmailResponse.class
            );
            
            return response.getBody();
            
        } catch (Exception e) {
            return new DispatcherEmailResponse(false, "Failed to send email via dispatcher: " + e.getMessage());
        }
    }
}