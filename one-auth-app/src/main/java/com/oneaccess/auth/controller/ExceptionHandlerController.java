package com.oneaccess.auth.controller;

import com.oneaccess.auth.services.common.GenericResponseDTO;
import com.oneaccess.auth.utils.exceptions.CustomAppException;
import com.oneaccess.auth.utils.exceptions.ResourceNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import jakarta.servlet.http.HttpServletRequest;

@Slf4j
@ControllerAdvice
public class ExceptionHandlerController {

    /**
     * Generate secure error ID for logging correlation.
     */
    private String generateErrorId() {
        return "ERR-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
    }

    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<?> resourceNotFoundException(final ResourceNotFoundException ex,
                                                       final HttpServletRequest request) {
        String errorId = generateErrorId();
        String requestPath = request.getRequestURI();
        
        log.warn("Resource not found - Error ID: {}, Path: {}, Details: {}", errorId, requestPath, ex.getMessage());
        
        GenericResponseDTO<String> response = new GenericResponseDTO<>(ex.getMessage(), null);
        response.setErrorId(errorId); // Allow client to reference error ID for support
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MethodArgumentTypeMismatchException.class)
    public ResponseEntity<?> methodArgumentTypeMismatchException(final MethodArgumentTypeMismatchException ex,
                                                                 final HttpServletRequest request) {
        String errorId = generateErrorId();
        String requestPath = request.getRequestURI();
        
        log.warn("Invalid request parameter - Error ID: {}, Path: {}, Parameter: {}",
                errorId, requestPath, ex.getName());
        
        GenericResponseDTO<String> response = new GenericResponseDTO<>("Invalid parameter: " + ex.getName(), null);
        response.setErrorId(errorId);
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<?> badCredentialsException(final BadCredentialsException ex,
                                                       final HttpServletRequest request) {
        String errorId = generateErrorId();
        String requestPath = request.getRequestURI();
        String userAgent = request.getHeader("User-Agent");
        String remoteAddr = request.getRemoteAddr();
        
        log.warn("Authentication failed - Error ID: {}, Path: {}, IP: {}, UserAgent: {}",
                errorId, requestPath, remoteAddr, userAgent);
        
        GenericResponseDTO<String> response = new GenericResponseDTO<>("Invalid credentials", null);
        response.setErrorId(errorId);
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(CustomAppException.class)
    public ResponseEntity<?> customAppException(final CustomAppException ex,
                                               final HttpServletRequest request) {
        String errorId = generateErrorId();
        String requestPath = request.getRequestURI();
        
        log.error("Application error - Error ID: {}, Path: {}, Details: {}",
                 errorId, requestPath, ex.getMessage());
        
        GenericResponseDTO<String> response = new GenericResponseDTO<>(ex.getMessage(), null);
        response.setErrorId(errorId);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<?> runtimeException(final RuntimeException ex,
                                             final HttpServletRequest request) {
        String errorId = generateErrorId();
        String requestPath = request.getRequestURI();
        
        log.error("Unexpected runtime error - Error ID: {}, Path: {}, Exception: {}",
                 errorId, requestPath, ex.getClass().getSimpleName(), ex);
        
        GenericResponseDTO<String> response = new GenericResponseDTO<>(ex.getMessage(), null);
        response.setErrorId(errorId);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Catch-all exception handler for any unhandled exceptions.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> genericException(final Exception ex,
                                            final HttpServletRequest request) {
        String errorId = generateErrorId();
        String requestPath = request.getRequestURI();
        
        log.error("Unhandled exception - Error ID: {}, Path: {}, Exception: {}", 
                 errorId, requestPath, ex.getClass().getSimpleName(), ex);
        
        GenericResponseDTO<String> response = new GenericResponseDTO<>(ex.getMessage(), null);
        response.setErrorId(errorId);
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
