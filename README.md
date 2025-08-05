# OneAuth 🔐

**Modern Authentication Platform for Enterprise Applications**

OneAuth is a production-ready authentication service designed for developers who need robust, scalable identity management. Built with Spring Boot and modern security standards, it provides everything needed to implement secure authentication in microservice architectures.

## Vision

**"Single source of truth for authentication across all your applications"**

*Powered by NeuroQAI's vision of intelligent, frictionless user experiences that adapt to human behavior.*

OneAuth solves the complexity of implementing secure authentication by providing:

- **Unified Identity**: One service, multiple applications
- **Developer-First**: Easy integration with comprehensive tooling
- **Production-Ready**: Enterprise-grade security and scalability
- **Cloud-Native**: Built for modern containerized deployments

## Architecture

- **one-auth-app**: Main Spring Boot application
- **one-auth-jar**: Reusable authentication library for integration
- **examples**: Demo applications showcasing integration

## ✨ Features

### Core Authentication

- 🔐 **JWT with RS256** - Industry-standard token signing with JWKS endpoint
- 🌐 **OAuth2 Social Login** - Google, Facebook, GitHub integration with PKCE
- 🚀 **Passwordless Authentication** - Magic links, OTP, and biometric integration for frictionless login
- 👤 **Complete User Lifecycle** - Registration, verification, password management
- 🔄 **Service-to-Service Auth** - Token exchange for microservice communication

### Developer Experience

- 📦 **Reusable Library** - Drop-in authentication for any Spring Boot app
- 🎯 **Multiple Profiles** - Simple, example, and hardened security configurations
- 📧 **Template Engine** - Customizable email templates with FreeMarker
- 🔍 **Health & Monitoring** - Built-in actuator endpoints for observability

### Production Features

- 💾 **Flexible Caching** - Redis or in-memory with configurable strategies
- 🏗️ **Multi-Module Architecture** - Clean separation of concerns
- 🐳 **Container Ready** - Optimized Docker builds with multi-stage process
- ⚡ **Performance Optimized** - Connection pooling, async processing

## 🚀 Quick Start

### Prerequisites

- **Java 17+** (LTS recommended)
- **Maven 3.6+**
- **Docker** (for containerized setup)

### Local Development

```bash
# Clone and build
git clone <repository-url>
cd one-auth
mvn clean package -DskipTests

# Run the application
java -jar one-auth-app/target/one-auth-app-0.0.1-SNAPSHOT.jar
```

### Docker Setup (Recommended)

```bash
# Complete stack with MySQL
docker-compose -f docker-compose-local.yml up

# Or just the app
docker build -t one-auth:latest .
docker run -p 8080:8080 one-auth:latest
```

🌐 **Access**: `http://localhost:8080`

### 🔗 API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| `GET` | `/health` | Application health check |
| `GET` | `/.well-known/jwks` | JSON Web Key Set for verification |
| `POST` | `/api/auth/login` | User authentication |
| `POST` | `/api/auth/register` | User registration |
| `GET` | `/oauth2/authorize` | OAuth2 authorization flow |
| `POST` | `/api/auth/token/exchange` | Service-to-service token exchange |

## ⚙️ Configuration

### Application Profiles

OneAuth supports multiple security configurations:

- `application.yml` - Main production configuration

### Core OneAuth Configuration

```yaml
# OneAuth Service Configuration
one-auth:
  application:
    app-id: "your-app-id"  # Required unique identifier
    
    # RSA Key Pair for JWT signing (required for service-to-service)
    key-pair:
      current-kid: ${AUTH_SERVER_IDENTITY_KID}
      private-key-b64: ${AUTH_SERVER_IDENTITY_PRIVATE_KEY}
      public-key-b64: ${AUTH_SERVER_IDENTITY_PUBLIC_KEY}
    
    # Public endpoints that don't require authentication
    app-exclusion-patterns:
      - "/actuator/health"
      - "/auth/**"
      - "/oauth2/**" 
      - "/.well-known/**"
    
    # Service-to-service authentication
    service-auth:
      # Note: Enabling will by default secure all endpoints for service-to-service auth. See examples projects.
      disabled: false  # Enable for microservice communication.

  # Auth server endpoints
  auth-server:
    base-url: ${AUTH_SERVER_SERVICE_URL:http://localhost:8080}
    jwks-api: "/.well-known/jwks.json"
    offline-mode: true  # Cache JWKS for offline validation
```

### Database & Infrastructure

```yaml
spring:
  # MySQL Configuration
  datasource:
    url: jdbc:mysql://${MYSQL_URL:localhost}:3306/${MYSQL_ONEAUTH_DB_NAME:oneauth-db}
    username: ${MYSQL_ONEAUTH_USERNAME:root}
    password: ${MYSQL_ONEAUTH_PASSWORD:root}
    
  # Redis Caching (Optional)
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      password: ${REDIS_PASSWORD}

# Cache Strategy
myapp:
  cache:
    type: memory  # Options: memory, redis
```

### OAuth2 Social Providers

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          google:
            clientId: ${GOOGLE_CLIENT_ID}
            clientSecret: ${GOOGLE_CLIENT_SECRET}
            scope: email, profile
            
          facebook:
            clientId: ${FACEBOOK_CLIENT_ID}
            clientSecret: ${FACEBOOK_CLIENT_SECRET}
            scope: email, public_profile
            
          github:
            clientId: ${GITHUB_CLIENT_ID}
            clientSecret: ${GITHUB_CLIENT_SECRET}
            scope: user, user:email
```

### Email Configuration

```yaml
spring:
  mail:
    host: ${MAIL_HOST:smtp.gmail.com}
    username: ${MAIL_USERNAME}
    password: ${MAIL_PASSWORD}
    port: ${MAIL_PORT:587}

myapp:
  mail:
    defaultEmailAddress: ${APP_EMAIL:support@oneaccess.com}
    verificationCodeExpirationSeconds: 10m
```

## Development

### Build

```bash
mvn clean package
```

### Tests

```bash
mvn test
```

### Docker Build

```bash
docker build -t one-auth:latest .
```

## CI/CD

GitHub Actions workflows:

- **PR builds**: Automatic build verification
- **Master builds**: Build and push to container registry

See [GITHUB_ACTIONS_SETUP.md](GITHUB_ACTIONS_SETUP.md) for configuration details.

## 🔧 Integration

### Using OneAuth Library

**1. Add Maven Dependency**

```xml
<dependency>
    <groupId>com.oneaccess.auth</groupId>
    <artifactId>one-auth-jar</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

**2. Configure Your Application**

```yaml
one-auth:
  jwks-url: http://localhost:8080/.well-known/jwks
  enabled: true
  cache-duration: PT15M  # 15 minutes
```

**3. Secure Your Endpoints**

```java
@RestController
@RequestMapping("/api/secure")
public class SecureController {
    
    @GetMapping("/profile")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<UserProfile> getProfile(Authentication auth) {
        // Your secured endpoint logic
    }
}
```

## 📚 Developer Resources

### Documentation

- __[OAuth Security Deep Dive](docs/OAuth_security_with_spring.md)__ - Comprehensive security guide
- **[Testing Guide](one-auth-app/TESTING.md)** - Test strategies and examples
- __[API Test Commands](one-auth-app/TEST_COMMANDS.md)__ - Ready-to-use API calls
- __[Demo Integration](examples/demo-app2/TEST_COMMANDS.md)__ - Working example application

### CI/CD Setup

- __[GitHub Actions](GITHUB_ACTIONS_SETUP.md)__ - Automated build and deployment setup
- **[Workflows README](.github/workflows/README.md)** - Detailed workflow documentation

## 🤝 Contributing

1. **Development Setup**: Follow Quick Start guide
2. **Code Style**: Use provided IDE configurations
3. **Testing**: Ensure all tests pass before PR
4. **Documentation**: Update relevant docs with changes

### Support

- **Issues**: Create GitHub issues for bugs and feature requests
- **Documentation**: Check existing guides before asking questions
- **Community**: Join discussions in repository discussions