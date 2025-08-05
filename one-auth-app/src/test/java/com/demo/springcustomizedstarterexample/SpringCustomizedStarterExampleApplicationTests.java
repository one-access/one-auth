package com.demo.springcustomizedstarterexample;

import com.oneaccess.auth.SpringCustomizedStarterExampleApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(classes = SpringCustomizedStarterExampleApplication.class)
@TestPropertySource(properties = {
    "spring.datasource.url=jdbc:h2:mem:testdb",
    "spring.datasource.driver-class-name=org.h2.Driver",
    "spring.jpa.hibernate.ddl-auto=create-drop",
    "one-auth.auth-server.offline-mode=true",
    "one-auth.application.app-id=test-app",
    "one-auth.application.key-pair.current-kid=test-kid",
    "one-auth.application.key-pair.private-key-env=TEST_PRIVATE_KEY",
    "one-auth.application.key-pair.public-key-env=TEST_PUBLIC_KEY"
})
class SpringCustomizedStarterExampleApplicationTests {

	@Test
	void contextLoads() {
		// Test passes if Spring context loads successfully
	}

}
