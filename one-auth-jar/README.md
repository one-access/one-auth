# One-Auth JAR Library

A comprehensive Spring Boot starter library that provides JWT-based authentication and authorization services for microservices. This library automatically secures your Spring Boot application endpoints with JWT validation, supports service-to-service authentication, and integrates seamlessly with the OneAuth ecosystem.

## Features

✅ **Auto-Configuration**: Automatic Spring Security configuration with zero-code setup  
✅ **JWT Token Validation**: Validates access tokens using RSA public keys from JWKS endpoints  
✅ **User Authentication**: Support for user JWT tokens via `Authorization: Bearer` header  
✅ **Service Authentication**: Service-to-service JWT authentication with fine-grained permissions  
✅ **JWKS Integration**: Automatic fetching and caching of public keys from auth server  
✅ **Public API Support**: Configure endpoints that bypass authentication  
✅ **Offline Mode**: Fallback to cached keys when auth server is unavailable  
✅ **Role-Based Access**: Supports user roles and Spring Security annotations  
✅ **App-Specific Permissions**: Fine-grained service access control with pattern matching  
✅ **Custom User Details**: Rich user context with roles, permissions, and metadata  
✅ **Production Ready**: Built for Spring Boot 3.x with comprehensive error handling

## Installation

Add the following dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>com.oneaccess.auth</groupId>
    <artifactId>one-auth-jar</artifactId>
    <version>${one-auth-jar.version}</version>
</dependency>
```

## Quick Start

### 1. Basic Configuration

Create an `application.yml` file with the minimum required configuration:

```yaml
one-auth:
  application:
    app-id: "YOUR_APP_ID"  # Unique identifier for your application
    
    # Required for service authentication and token creation
    key-pair:
      current-kid: ${YOUR_APP_IDENTITY_KID}
      private-key-env: ${YOUR_APP_IDENTITY_PRIVATE_KEY}
      public-key-env: ${YOUR_APP_IDENTITY_PUBLIC_KEY}
    
    # Public APIs that don't require authentication
    public-api-patterns:
      - "/health"
      - "/actuator/health" 
      - "/api/public/**"
  
  auth-server:
    base-url: ${AUTH_SERVER_URL}
    jwks-api: "/.well-known/jwks.json"
    offline-mode: false  # Set to true for offline development
```

### 2. Environment Variables

Create a `.env` file or set these environment variables:

```env
# Application Identity (Required)
YOUR_APP_IDENTITY_KID=your-key-id-here
YOUR_APP_IDENTITY_PRIVATE_KEY=-----BEGIN PRIVATE KEY-----...-----END PRIVATE KEY-----
YOUR_APP_IDENTITY_PUBLIC_KEY=-----BEGIN PUBLIC KEY-----...-----END PUBLIC KEY-----

# Auth Server Configuration
AUTH_SERVER_URL=http://localhost:8080
SERVER_PORT=8082
```

### 3. Complete Configuration Example

For production use with service-to-service authentication:

```yaml
one-auth:
  application:
    app-id: ""  # Your application ID
    
    # Key pair configuration
    key-pair:
      current-kid: ${DEMO2_SERVICE_IDENTITY_KID}
      private-key-env: ${DEMO2_SERVICE_IDENTITY_PRIVATE_KEY}
      public-key-env: ${DEMO2_SERVICE_IDENTITY_PUBLIC_KEY}
    
    # Public APIs (no authentication needed)
    public-api-patterns:
      - "api/demo/public"
      - "/health"
      - "/actuator/health"
      - "/swagger-ui/**"
    
    # Service-to-service authentication patterns
    service-auth:
      api-patterns:
        # Specific service access control
        - pattern: "*/services/payments/**"
          app-permissions:
            "0200": ["READ", "WRITE"]  # Payment service has full access
            "0300": ["READ"]           # Analytics service read-only
        
        # Universal service access
        - pattern: "*/services/**"
          app-permissions:
            "*": ["READ", "WRITE"]     # All valid service tokens
  
  auth-server:
    base-url: ${AUTH_SERVER_SERVICE_URL}
    jwks-api: "/.well-known/jwks.json"
    offline-mode: false

# Server configuration
server:
  port: ${SERVER_PORT:8082}
  
# Enable detailed logging for troubleshooting
logging:
  level:
    com.oneaccess: INFO
    org.springframework.security: DEBUG
```

### Service Identity Configuration

To configure your service to call other services with service-to-service authentication:

```yaml
one-auth:
  # Service identity configuration (for calling other services)
  service:
    app-id: "your-service-id"
    kid: "your-service-key-id"
    
    # Option 1: Use private key file
    private-key-path: "classpath:keys/your-service-private-key.pem"
    
    # Option 2: Use base64-encoded private key directly in configuration
    # private-key-base64: "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCr58JjLeRkVUCEQc8Dj2NjMZ3HsLb/egbrwskg..."
```

You can use either `private-key-path` or `private-key-base64` to provide the private key. Using the base64-encoded option allows you to include the private key directly in your configuration without needing a separate file.

## Usage

### Enable Method Security

Add `@EnableMethodSecurity` to your main application class:

```java
@SpringBootApplication
@EnableMethodSecurity(
        securedEnabled = true,
        jsr250Enabled = true,
        prePostEnabled = true
)
public class YourApplication {
    public static void main(String[] args) {
        SpringApplication.run(YourApplication.class, args);
    }
}
```

### Secure Endpoints with Annotations

Use Spring Security annotations to secure your endpoints:

```java
@RestController
@RequestMapping("/api")
public class YourController {

    // Public endpoint - no authentication required
    @GetMapping("/public")
    public String publicEndpoint() {
        return "This is a public endpoint";
    }

    // Secure endpoint - requires user JWT with ADMIN role
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @GetMapping("/admin")
    public String adminEndpoint() {
        return "This is an admin endpoint";
    }

    // User endpoint - requires valid user JWT
    @GetMapping("/user")
    public String userEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Hello, " + auth.getName();
    }
    
    // Service endpoint - requires service-to-service JWT
    @GetMapping("/service/data")
    public String serviceEndpoint() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        return "Service: " + auth.getName();
    }
}
```

## Authentication Flow

### User Authentication

1. User logs in to the authentication service (e.g., one-auth-app)
2. Authentication service validates credentials and issues a JWT
3. Client includes the JWT in the `Authorization: Bearer <token>` header
4. One-auth-jar validates the JWT and sets up the security context

### Service-to-Service Authentication

1. Service A needs to call Service B
2. Service A generates a JWT using its private key
3. Service A includes the JWT in the `X-App-Auth: <token>` header
4. Service B validates the JWT using the JWK endpoint
5. One-auth-jar validates the JWT and sets up the security context

## Key Management

### Using the Key Generator Utility

One Auth Jar includes a built-in key generator utility that simplifies the creation of RSA key pairs and JWK configuration. This utility generates all the necessary keys and formats them properly for use with the library.

To use the key generator:

```bash
# Run the key generator utility
java -cp one-auth-jar.jar com.oneaccess.authjar.util.KeyGenerator

# Follow the prompts to specify your service ID and output directory
```

The utility will generate:
1. A JWK set file containing your public key in JWK format
2. A private key file in PEM format
3. A Base64-encoded private key for direct use in application.yml

It also provides configuration examples for your application.yml file.

### Manual Key Generation (Alternative)

If you prefer to generate keys manually:

1. Generate a private key for your service:
   ```bash
   openssl genrsa -out your-service-private-key.pem 2048
   ```

2. Extract the public key from the private key:
   ```bash
   openssl rsa -in your-service-private-key.pem -pubout -out your-service-public-key.pem
   ```

3. Add your service's public key to the JWK set in the authentication service:
   ```json
   {
     "keys": [
       {
         "kty": "RSA",
         "use": "sig",
         "kid": "your-service-key-id",
         "alg": "RS256",
         "n": "your-base64-encoded-modulus",
         "e": "AQAB"
       }
     ]
   }
   ```

## Testing

### Demo Application Testing

The `demo-app2` application provides a complete example of one-auth-jar integration:

#### 1. Start Required Services

**Start MySQL Database:**
```bash
docker run -d --name oneauth-mysql \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=oneauth-db \
  -p 3306:3306 mysql:8
```

**Start OneAuth App (Auth Server):**
```bash
cd one-auth-app
mvn spring-boot:run
# Runs on http://localhost:8080
```

**Start Demo App2 (Client Application):**
```bash
cd demo-app2
mvn spring-boot:run
# Runs on http://localhost:8082
```

#### 2. Test Scenarios

**Test Public Endpoints (No Authentication Required):**
```bash
# Health check
curl -i http://localhost:8082/actuator/health

# Public demo endpoint
curl -i http://localhost:8082/api/demo/public
```

**Test Protected Endpoints (Should Return 401 Unauthorized):**
```bash
curl -i http://localhost:8082/api/demo/user
curl -i http://localhost:8082/api/demo/secure
```

**Register User and Get JWT Token:**
```bash
# Register new user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","fullName":"Test User","password":"password123"}'

# Login and get JWT token
JWT_TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  | jq -r '.token')

echo "JWT Token: $JWT_TOKEN"
```

**Test with Valid JWT Token:**
```bash
# Test protected user endpoint
curl -i http://localhost:8082/api/demo/user \
  -H "Authorization: Bearer $JWT_TOKEN"

# Test protected secure endpoint  
curl -i http://localhost:8082/api/demo/secure \
  -H "Authorization: Bearer $JWT_TOKEN"
```

#### 3. Complete Test Script

Use the provided test commands for comprehensive testing:

```bash
# Set environment variables
export AUTH_HOST="http://localhost:8080"
export DEMO_HOST="http://localhost:8082"

# Run comprehensive test
curl $DEMO_HOST/api/demo/public && \
curl $DEMO_HOST/api/demo/user && \
curl -X POST $AUTH_HOST/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","fullName":"Test User","password":"password123"}' && \
export JWT_TOKEN=$(curl -s -X POST $AUTH_HOST/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  | jq -r '.token') && \
echo "JWT: $JWT_TOKEN" && \
curl $DEMO_HOST/api/demo/user -H "Authorization: Bearer $JWT_TOKEN" && \
curl $DEMO_HOST/api/demo/secure -H "Authorization: Bearer $JWT_TOKEN"
```

#### 4. Expected Results

| Test Case | Expected Result | Status Code |
|-----------|----------------|-------------|
| Public endpoint without token | ✅ Success with message | 200 |
| Protected endpoint without token | ❌ Unauthorized | 401 |
| Protected endpoint with invalid token | ❌ Forbidden | 403 |
| Protected endpoint with valid token | ✅ Success with user data | 200 |
| Service endpoint with user token | ❌ Forbidden (if configured) | 403 |
| Service endpoint with valid service token | ✅ Success | 200 |

### Maven Testing

**Run Unit Tests:**
```bash
mvn test
```

**Build and Test:**
```bash
mvn clean install
```

**Run with Environment Variables:**
```bash
# Using .env file
mvn spring-boot:run -Dspring-boot.run.environmentVariables="$(cat .env | tr '\n' ',' | sed 's/,$//')"

# Or with specific variables
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-DSERVER_PORT=8082 -DAUTH_SERVER_URL=http://localhost:8080"
```

### Docker Compose Testing

The project includes a Docker Compose setup for complete testing:

```bash
# Start all services with Docker Compose
cd one-auth
docker-compose up -d

# Check service status
docker-compose ps

# View logs
docker-compose logs -f app

# Run comprehensive tests
./test-comprehensive.sh

# Stop services
docker-compose down
```

## Troubleshooting

### Common Issues

#### 1. Bean Configuration Error

**Error**: `The bean 'objectMapper', defined in class path resource [com/oneaccess/authjar/OneAuthBeanConfiguration.class], could not be registered`

**Solution**: Add bean override configuration:
```yaml
spring:
  main:
    allow-bean-definition-overriding: true
```

#### 2. JWKS Refresh Failed

**Error**: `JWKS refresh failed` or `Connection refused`

**Solutions**:
- Verify auth server is running on correct port
- Check `auth-server.base-url` configuration  
- Use offline mode for development:
```yaml
one-auth:
  auth-server:
    offline-mode: true
```

#### 3. Public Key Configuration Error

**Error**: `one-auth.application.key-pair.public-key-env must be configured`  

**Solution**: Ensure environment variables are properly set:
```bash
export YOUR_APP_IDENTITY_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A...
-----END PUBLIC KEY-----"
```

#### 4. JWT Token Validation Fails

**Error**: `403 Forbidden` for valid-looking tokens

**Solutions**:
- Check token expiration time
- Verify JWKS endpoint is accessible
- Ensure clock synchronization between services
- Validate JWT token format and signature
- Check if user has required roles/permissions

#### 5. Service Authentication Issues

**Error**: Service tokens are rejected

**Solutions**:
- Verify `app-id` matches in configuration
- Check service has proper permissions in `api-patterns`
- Ensure service token is valid and not expired
- Validate service key configuration

#### 6. Port Already in Use

**Error**: `Port 8080/8082 is already in use`

**Solution**: Kill existing processes or change ports:
```bash
# Find and kill processes
lsof -ti:8080 | xargs kill -9
lsof -ti:8082 | xargs kill -9

# Or change port in configuration
SERVER_PORT=8083
```

### Debug Configuration

Enable comprehensive logging for troubleshooting:

```yaml
logging:
  level:
    com.oneaccess.authjar: DEBUG
    org.springframework.security: DEBUG
    org.springframework.web: DEBUG
    org.springframework.boot.web: DEBUG
  pattern:
    console: "%d{yyyy-MM-dd HH:mm:ss} [%thread] %-5level %logger{36} - %msg%n"
```

### Health Checks

Monitor application health:

```bash
# Application health
curl http://localhost:8082/actuator/health

# Detailed info (if enabled)
curl http://localhost:8082/actuator/info

# Check auth server connectivity
curl http://localhost:8080/.well-known/jwks.json
```

### Testing Individual Components

**Test JWT Token Validation:**
```java
@Autowired
private OneAuthJwtService jwtService;

@Test
public void testTokenValidation() {
    String token = "your-jwt-token";
    try {
        Claims claims = jwtService.validateToken(token);
        System.out.println("Token valid: " + claims.getSubject());
    } catch (Exception e) {
        System.out.println("Token invalid: " + e.getMessage());
    }
}
```

**Test JWKS Manager:**
```java
@Autowired
private JwksManager jwksManager;

@Test  
public void testJwksManager() {
    try {
        jwksManager.refreshJwks();
        System.out.println("JWKS refresh successful");
    } catch (Exception e) {
        System.out.println("JWKS refresh failed: " + e.getMessage());
    }
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.