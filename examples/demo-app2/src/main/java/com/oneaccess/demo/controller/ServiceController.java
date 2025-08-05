package com.oneaccess.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/services")
public class ServiceController {


    /**
     * Service endpoint - requires service token
     * This is automatically validated by the filter based on the pattern in configuration.
     * No @PreAuthorize needed as the filter handles validation.
     */
    @GetMapping("/service")
    public String serviceEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Service endpoint - requires service JWT (X-Service-Token). Service: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

    /**
     * Service endpoint with explicit @PreAuthorize
     * This is redundant with filter validation but shows how to use @PreAuthorize if needed.
     */
    @PreAuthorize("hasAuthority('SERVICE_TOKEN')")
    @GetMapping("/service-with-preauth")
    public String serviceWithPreauthEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Service endpoint with @PreAuthorize - requires service JWT. Service: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

    /**
     * Mode 2: App-Specific Control endpoint
     * This is also automatically validated by the filter based on the pattern in configuration.
     * Only specific apps with specific scopes can access this endpoint.
     */
    @GetMapping("/payments/app-specific")
    public String appSpecificEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "App-specific endpoint - only specific apps with specific scopes can access. Service: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

    /**
     * Endpoint with scope-specific @PreAuthorize
     * This shows how to use @PreAuthorize with the new scope-specific authorities.
     */
    @PreAuthorize("hasAuthority('SERVICE_APP_PAYMENT_SERVICE_WRITE')")
    @GetMapping("/payments/write")
    public String paymentWriteEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Payment write endpoint - requires payment-service with WRITE scope. Service: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

    /**
     * Endpoint with scope-specific @PreAuthorize
     * This shows how to use @PreAuthorize with the new scope-specific authorities.
     */
    @PreAuthorize("hasAuthority('SERVICE_APP_PAYMENT_SERVICE_READ') or hasAuthority('SERVICE_APP_ADMIN_SERVICE_READ')")
    @GetMapping("/payments/read")
    public String paymentReadEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Payment read endpoint - requires payment-service or admin-service with READ scope. Service: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

    /**
     * Mode 2 with wildcard: READ-only access for all service apps
     * This is automatically validated by the filter based on the pattern in configuration.
     * Any valid service token can access this endpoint, but only with READ scope.
     */
    @PreAuthorize("hasAuthority('ROLE_SERVICE')")
    @GetMapping("/all-services")
    public String readOnlyForAllServicesEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "READ-only for all services endpoint - any valid service token can access with READ scope. Service: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

    /**
     * Mode 2 with wildcard: READ-only access with explicit @PreAuthorize
     * This shows how to use @PreAuthorize to enforce the READ scope.
     */
    @PreAuthorize("hasAuthority('SERVICE_TOKEN') and hasAuthority('SERVICE_APP_' + authentication.name.toUpperCase() + '_READ')")
    @GetMapping("/readonly/with-preauth")
    public String readOnlyWithPreauthEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "READ-only with @PreAuthorize - requires service token with READ scope. Service: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

}
