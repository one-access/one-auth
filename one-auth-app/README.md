# OneAuth Authentication Server

Spring Boot authentication server providing JWT tokens, user management, and JWKS endpoint for the OneAuth system.

## Features

- **User Authentication**: Registration, login, password reset
- **JWT Token Generation**: Secure JWT tokens with RSA signing
- **JWKS Endpoint**: Standard `.well-known/jwks.json` serving public keys for all applications  
- **OAuth2 Integration**: Google, Facebook, GitHub login support
- **Database Integration**: MySQL for user storage
- **Security**: Spring Security with custom JWT filters

## Quick Start

### 1. Database Setup
```bash
docker run -d --name oneauth-mysql \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=oneauth-db \
  -p 3306:3306 mysql:8
```

### 2. Start Server
```bash
mvn spring-boot:run \
  -DSERVER_PORT=8080 \
  -DMYSQL_URL=localhost \
  -DMYSQL_ONEAUTH_USERNAME=root \
  -DMYSQL_ONEAUTH_PASSWORD=root
```

### 3. Test Authentication
```bash
# Register user
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","fullName":"Test User","password":"password123"}'

# Login and get JWT token
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}'
```

## Endpoints

### Authentication
- `POST /auth/register` - User registration
- `POST /auth/login` - User login (returns JWT token)
- `POST /auth/send-forgot-password` - Password reset request
- `GET /users/me` - Get current user (requires JWT)

### JWKS
- `GET /.well-known/jwks.json` - Public keys for JWT verification

### Health & Monitoring
- `GET /actuator/health` - Application health check
- `GET /actuator/info` - Application information

## Configuration

Environment variables for Maven:
```bash
mvn spring-boot:run \
  -DSERVER_PORT=8080 \
  -DMYSQL_URL=localhost \
  -DMYSQL_PORT=3306 \
  -DMYSQL_ONEAUTH_DB_NAME=oneauth-db \
  -DMYSQL_ONEAUTH_USERNAME=root \
  -DMYSQL_ONEAUTH_PASSWORD=root \
  -DAUTH_SERVER_IDENTITY_KID=BA8A7D28-F226-48F3-B064-535D3E5FF1F5 \
  -DAUTH_SERVER_IDENTITY_PRIVATE_KEY="<private-key>" \
  -DAUTH_SERVER_IDENTITY_PUBLIC_KEY="<public-key>"
```

## Testing

See `TESTING.md` for comprehensive testing procedures including:
- Complete test suite automation
- Manual API testing  
- JWKS endpoint validation
- Integration testing with demo applications

## Architecture

This server integrates with:
- **one-auth-jar**: Provides JWT authentication library
- **demo-app2**: Demo application consuming JWT tokens
- **dispatcher-app**: Email service with service-to-service authentication

**Port**: 8080  
**Database**: MySQL  
**Authentication**: JWT with RSA signatures  
**Standards**: JWKS (RFC 7517), JWT (RFC 7519)