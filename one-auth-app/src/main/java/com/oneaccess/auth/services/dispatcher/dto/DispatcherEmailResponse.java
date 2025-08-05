package com.oneaccess.auth.services.dispatcher.dto;

public class DispatcherEmailResponse {
    
    private boolean success;
    private String message;
    private String messageId;
    
    public DispatcherEmailResponse() {}
    
    public DispatcherEmailResponse(boolean success, String message) {
        this.success = success;
        this.message = message;
    }
    
    public DispatcherEmailResponse(boolean success, String message, String messageId) {
        this.success = success;
        this.message = message;
        this.messageId = messageId;
    }
    
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public String getMessageId() {
        return messageId;
    }
    
    public void setMessageId(String messageId) {
        this.messageId = messageId;
    }
}