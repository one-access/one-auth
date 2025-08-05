package com.oneaccess.auth.services.dispatcher.dto;

import java.util.Map;

public class DispatcherEmailRequest {
    
    private String templateId;
    private String sourceAppId;
    private String to;
    private String from;
    private Map<String, Object> variables;
    
    public DispatcherEmailRequest() {}
    
    public DispatcherEmailRequest(String templateId, String sourceAppId, String to, Map<String, Object> variables) {
        this.templateId = templateId;
        this.sourceAppId = sourceAppId;
        this.to = to;
        this.variables = variables;
    }
    
    public String getTemplateId() {
        return templateId;
    }
    
    public void setTemplateId(String templateId) {
        this.templateId = templateId;
    }
    
    public String getSourceAppId() {
        return sourceAppId;
    }
    
    public void setSourceAppId(String sourceAppId) {
        this.sourceAppId = sourceAppId;
    }
    
    public String getTo() {
        return to;
    }
    
    public void setTo(String to) {
        this.to = to;
    }
    
    public String getFrom() {
        return from;
    }
    
    public void setFrom(String from) {
        this.from = from;
    }
    
    public Map<String, Object> getVariables() {
        return variables;
    }
    
    public void setVariables(Map<String, Object> variables) {
        this.variables = variables;
    }
}