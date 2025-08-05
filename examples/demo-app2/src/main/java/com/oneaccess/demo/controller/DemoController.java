package com.oneaccess.demo.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Demo controller showing different authentication and authorization approaches.
 *
 * Demonstrates:
 * 1. Public endpoints (no auth)
 * 2. Automatic validation by filter (no @PreAuthorize needed)
 * 3. @PreAuthorize with role-based authorities
 * 4. @PreAuthorize with service token authorities
 * 5. @PreAuthorize with app-specific scope authorities
 */

@RestController
@RequestMapping("/api/demo")
public class DemoController {

    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint - no JWT required";
    }

    @PreAuthorize("hasAuthority('ROLE_USER')")
    @GetMapping("/user")
    public String userEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "User endpoint - accepts specific to role: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }
    
    @PreAuthorize("hasAuthority('USER_TOKEN') or hasAuthority('SERVICE_TOKEN')")
    @GetMapping("/hybrid")
    public String eitherUserRoleOrServiceToken() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Hybrid endpoint - accepts user OR service JWT. Principal: " + auth.getName() + 
               ", Authorities: " + auth.getAuthorities();
    }

    @PreAuthorize("hasAuthority('USER_TOKEN') and hasAuthority('SERVICE_TOKEN')")
    @GetMapping("/both-required")
    public String bothTokensEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Both tokens required - needs user JWT AND service JWT. Principal: " + auth.getName() +
                ", Authorities: " + auth.getAuthorities();
    }

}