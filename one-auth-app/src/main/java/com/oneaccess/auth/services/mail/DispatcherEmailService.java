package com.oneaccess.auth.services.mail;

import com.oneaccess.auth.config.AppProperties;
import com.oneaccess.auth.services.dispatcher.DispatcherClient;
import com.oneaccess.auth.services.dispatcher.dto.DispatcherEmailRequest;
import com.oneaccess.auth.services.dispatcher.dto.DispatcherEmailResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Service
public class DispatcherEmailService {
    
    private static final Logger logger = LoggerFactory.getLogger(DispatcherEmailService.class);
    private static final String SOURCE_APP_ID = "one-auth-app";
    
    private final DispatcherClient dispatcherClient;
    private final AppProperties appProperties;
    
    @Autowired
    public DispatcherEmailService(DispatcherClient dispatcherClient, AppProperties appProperties) {
        this.dispatcherClient = dispatcherClient;
        this.appProperties = appProperties;
    }
    
    public boolean sendVerificationEmail(String userEmail) {
        try {
            String[] fullNameArray = extractUserFullName(userEmail);
            String firstName = fullNameArray.length > 0 ? fullNameArray[0] : "";
            
            String officialCompanyDomain = appProperties.getOfficialCompanyDomain();
            String linkVerifyEmail = UriComponentsBuilder
                .fromUriString(officialCompanyDomain + "/verify")
                .queryParam("email", userEmail)
                .queryParam("isProcessVerifyEmail", true)
                .build().toUriString();
            
            Map<String, Object> variables = new HashMap<>();
            variables.put("firstName", firstName);
            variables.put("linkEmailVerification", linkVerifyEmail);
            
            DispatcherEmailRequest request = new DispatcherEmailRequest(
                "verification-email", 
                SOURCE_APP_ID, 
                userEmail, 
                variables
            );
            
            DispatcherEmailResponse response = dispatcherClient.sendEmail(request);
            
            if (response.isSuccess()) {
                logger.info("Verification email sent successfully to: {}", userEmail);
                return true;
            } else {
                logger.error("Failed to send verification email to {}: {}", userEmail, response.getMessage());
                return false;
            }
            
        } catch (Exception e) {
            logger.error("Error sending verification email to {}: {}", userEmail, e.getMessage(), e);
            return false;
        }
    }
    
    public boolean sendPasswordResetEmail(String userEmail) {
        try {
            String[] fullNameArray = extractUserFullName(userEmail);
            String firstName = fullNameArray.length > 0 ? fullNameArray[0] : "";
            
            String officialCompanyDomain = appProperties.getOfficialCompanyDomain();
            String linkPasswordReset = UriComponentsBuilder
                .fromUriString(officialCompanyDomain + "/reset-password")
                .queryParam("email", userEmail)
                .queryParam("isProcessPasswordReset", true)
                .build().toUriString();
            
            Map<String, Object> variables = new HashMap<>();
            variables.put("firstName", firstName);
            variables.put("linkPasswordReset", linkPasswordReset);
            
            DispatcherEmailRequest request = new DispatcherEmailRequest(
                "password-reset", 
                SOURCE_APP_ID, 
                userEmail, 
                variables
            );
            
            DispatcherEmailResponse response = dispatcherClient.sendEmail(request);
            
            if (response.isSuccess()) {
                logger.info("Password reset email sent successfully to: {}", userEmail);
                return true;
            } else {
                logger.error("Failed to send password reset email to {}: {}", userEmail, response.getMessage());
                return false;
            }
            
        } catch (Exception e) {
            logger.error("Error sending password reset email to {}: {}", userEmail, e.getMessage(), e);
            return false;
        }
    }
    
    public boolean sendWelcomeEmail(String userEmail, String fullName) {
        try {
            String[] fullNameArray = fullName != null ? fullName.split(" ") : new String[]{""};
            String firstName = fullNameArray.length > 0 ? fullNameArray[0] : "";
            
            Map<String, Object> variables = new HashMap<>();
            variables.put("firstName", firstName);
            variables.put("setupItemList", Arrays.asList(
                "Complete your profile setup",
                "Verify your contact information",
                "Explore available features",
                "Set up your preferences"
            ));
            
            DispatcherEmailRequest request = new DispatcherEmailRequest(
                "welcome-email", 
                SOURCE_APP_ID, 
                userEmail, 
                variables
            );
            
            DispatcherEmailResponse response = dispatcherClient.sendEmail(request);
            
            if (response.isSuccess()) {
                logger.info("Welcome email sent successfully to: {}", userEmail);
                return true;
            } else {
                logger.error("Failed to send welcome email to {}: {}", userEmail, response.getMessage());
                return false;
            }
            
        } catch (Exception e) {
            logger.error("Error sending welcome email to {}: {}", userEmail, e.getMessage(), e);
            return false;
        }
    }
    
    private String[] extractUserFullName(String email) {
        String username = email.split("@")[0];
        return username.split("\\.");
    }
}