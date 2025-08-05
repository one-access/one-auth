# OneAuth App Testing Guide

Complete testing guide for the OneAuth authentication server with JWKS, login, registration, and demo app integration.

## Quick Start

### 1. Start Database
```bash
docker run -d --name oneauth-mysql \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=oneauth-db \
  -p 3306:3306 mysql:8
```

### 2. Start Auth Server
```bash
cd one-auth-app
mvn spring-boot:run -DSERVER_PORT=8080 -DMYSQL_URL=localhost -DMYSQL_ONEAUTH_USERNAME=root -DMYSQL_ONEAUTH_PASSWORD=root
```

### 3. Run Complete Test Suite
```bash
cd ..
chmod +x test-complete-flow.sh
./test-complete-flow.sh
```

## Environment Variables with Maven

Pass environment variables directly to Maven using `-D` flags:

```bash
mvn spring-boot:run \
  -DSERVER_PORT=8080 \
  -DMYSQL_URL=localhost \
  -DMYSQL_PORT=3306 \
  -DMYSQL_ONEAUTH_DB_NAME=oneauth-db \
  -DMYSQL_ONEAUTH_USERNAME=root \
  -DMYSQL_ONEAUTH_PASSWORD=root \
  -DAUTH_SERVER_IDENTITY_KID=BA8A7D28-F226-48F3-B064-535D3E5FF1F5 \
  -DAUTH_SERVER_IDENTITY_PRIVATE_KEY="$(cat ../one-auth-app/.env | grep AUTH_SERVER_IDENTITY_PRIVATE_KEY | cut -d'=' -f2-)" \
  -DAUTH_SERVER_IDENTITY_PUBLIC_KEY="$(cat ../one-auth-app/.env | grep AUTH_SERVER_IDENTITY_PUBLIC_KEY | cut -d'=' -f2-)"
```

Or use the provided script:
```bash
../run-with-env.sh
```

## JWKS Endpoint

The JWKS endpoint serves public keys for all applications following JWT standard:

### Endpoint
```
GET /.well-known/jwks.json
```

### Standard Format
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "BA8A7D28-F226-48F3-B064-535D3E5FF1F5",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

### Applications Included
- **Auth Server (1007)**: `kid: BA8A7D28-F226-48F3-B064-535D3E5FF1F5`
- **Demo App (0100)**: `kid: 401E1A2E-0F55-455D-94B6-B05C82C2F25C`  
- **Dispatcher (0200)**: `kid: 502F3B4C-1234-5678-9ABC-DEF012345678`

### Test JWKS
```bash
curl http://localhost:8080/.well-known/jwks.json | jq '.'
curl http://localhost:8080/.well-known/jwks.json | jq '.keys | length'  # Should return 3
```

## Authentication Testing

### 1. User Registration
```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "fullName": "Test User", 
    "password": "password123"
  }'
```

### 2. User Login
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

### 3. Extract JWT Token
```bash
JWT_TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com","password":"password123"}' \
  | jq -r '.token')

echo "Token: $JWT_TOKEN"
```

### 4. Test Protected Endpoints
```bash
# Should work with token
curl -H "Authorization: Bearer $JWT_TOKEN" http://localhost:8080/users/me

# Should return 401 without token  
curl http://localhost:8080/users/me
```

## Demo App Integration

### 1. Start Demo App
```bash
cd ../demo-app2
mvn spring-boot:run -DSERVER_PORT=8082
```

### 2. Test Integration
```bash
# Public endpoint (should work)
curl http://localhost:8082/api/demo/public

# Protected endpoint without token (should return 401)
curl http://localhost:8082/api/demo/user

# Protected endpoint with token (should work)
curl -H "Authorization: Bearer $JWT_TOKEN" http://localhost:8082/api/demo/user
```

## Complete Test Flow

### Sequential Commands
```bash
# 1. Start database
docker run -d --name oneauth-mysql -e MYSQL_ROOT_PASSWORD=root -e MYSQL_DATABASE=oneauth-db -p 3306:3306 mysql:8

# 2. Start auth server (in terminal 1)
cd one-auth-app && mvn spring-boot:run -DSERVER_PORT=8080 -DMYSQL_URL=localhost -DMYSQL_ONEAUTH_USERNAME=root -DMYSQL_ONEAUTH_PASSWORD=root

# 3. Start demo app (in terminal 2)  
cd demo-app2 && mvn spring-boot:run -DSERVER_PORT=8082

# 4. Run tests (in terminal 3)
cd .. && ./test-complete-flow.sh
```

### Automated Testing
The test suite validates:
- ✅ JWKS endpoint with all 3 application keys
- ✅ User registration and login
- ✅ JWT token generation and validation
- ✅ Protected endpoint authorization
- ✅ Demo app integration
- ✅ Error handling and security

## Test Results

Expected output:
```
=== OneAuth Complete Testing Suite ===
✅ Auth server is running
✅ JWKS endpoint accessible
✅ JWKS has valid structure with 3 keys
✅ Auth server key found (BA8A7D28...)
✅ Demo app key found (401E1A2E...)  
✅ Dispatcher key found (502F3B4C...)
✅ User registration - PASSED
✅ User login - PASSED
✅ JWT token extracted successfully
✅ Protected endpoint with JWT - PASSED
✅ Unauthorized access properly blocked
✅ Demo app integration working

🎉 All tests passed! OneAuth system is working correctly.
```

## Maven Environment Variables

### Method 1: Direct Command Line
```bash
mvn spring-boot:run -DKEY=value -DKEY2=value2
```

### Method 2: Using Script
```bash
#!/bin/bash
mvn spring-boot:run \
  -DSERVER_PORT=8080 \
  -DMYSQL_URL=localhost \
  -DMYSQL_ONEAUTH_USERNAME=root \
  -DMYSQL_ONEAUTH_PASSWORD=root
```

### Method 3: Environment + Maven
```bash
export SERVER_PORT=8080
export MYSQL_URL=localhost
mvn spring-boot:run
```

## Troubleshooting

### Database Connection Issues
```bash
# Check MySQL is running
docker ps | grep mysql

# Test connection
mysql -h localhost -u root -p oneauth-db

# Restart if needed
docker restart oneauth-mysql
```

### Port Conflicts
```bash
# Kill processes on ports
lsof -ti:8080 | xargs kill -9
lsof -ti:8082 | xargs kill -9

# Use different ports
mvn spring-boot:run -DSERVER_PORT=8081
```

### Environment Variables Not Loading
```bash
# Verify variables are set
echo $SERVER_PORT
echo $MYSQL_URL

# Export from .env file
export $(cat .env | grep -v '^#' | xargs)
```

## Performance Testing

### Load Test Login Endpoint
```bash
# Using curl in loop
for i in {1..10}; do
  curl -s -X POST http://localhost:8080/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"test@example.com","password":"password123"}' &
done
wait
```

### JWKS Performance
```bash
# Measure response time
time curl -s http://localhost:8080/.well-known/jwks.json > /dev/null
```

This testing guide provides complete coverage of the OneAuth system with standard JWKS format, proper Maven environment variable handling, and comprehensive test scenarios.