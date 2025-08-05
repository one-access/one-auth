package com.oneaccess.authjar.config;

import org.springframework.beans.factory.config.YamlPropertiesFactoryBean;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.EncodedResource;
import org.springframework.core.io.support.PropertySourceFactory;

import java.io.IOException;
import java.util.Properties;

/**
 * Factory for creating property sources from YAML files.
 * This class is used by the @PropertySource annotation to load YAML files.
 */
public class YamlPropertySourceFactory implements PropertySourceFactory {
    
    @Override
    public PropertySource<?> createPropertySource(String name, EncodedResource encodedResource) 
            throws IOException {
        Resource resource = encodedResource.getResource();
        
        if (resource.exists()) {
            String sourceName = name != null ? name : resource.getFilename();
            Properties properties = loadYamlProperties(resource);
            return new PropertiesPropertySource(sourceName, properties);
        } else {
            // Return an empty property source if the resource doesn't exist
            return new PropertiesPropertySource(name != null ? name : "empty", new Properties());
        }
    }
    
    /**
     * Loads properties from a YAML file.
     * 
     * @param resource The YAML resource
     * @return The properties
     */
    private Properties loadYamlProperties(Resource resource) {
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(resource);
        factory.afterPropertiesSet();
        return factory.getObject();
    }
}