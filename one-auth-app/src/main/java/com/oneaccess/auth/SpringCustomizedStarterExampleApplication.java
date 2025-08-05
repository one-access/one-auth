package com.oneaccess.auth;

import com.oneaccess.auth.config.AppProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

@SpringBootApplication
@EnableJpaAuditing(auditorAwareRef = "auditorAwareUserImpl")
@EnableConfigurationProperties(AppProperties.class)
public class SpringCustomizedStarterExampleApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringCustomizedStarterExampleApplication.class, args);
    }

}
