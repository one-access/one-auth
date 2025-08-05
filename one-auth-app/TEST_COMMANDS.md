# OneAuth App - API Testing Commands

Complete manual testing guide for the OneAuth authentication server with curl commands for all endpoints.

## Application Overview

- **Application**: OneAuth Authentication Server
- **Base URL**: `http://localhost:8080`
- **Port**: 8080
- **Database**: MySQL (oneauth-db)

## Prerequisites

### 1. Start the Application
```bash
cd one-auth-app
mvn spring-boot:run \
  -DSERVER_PORT=8080 \
  -DMYSQL_URL=localhost \
  -DMYSQL_ONEAUTH_USERNAME=root \
  -DMYSQL_ONEAUTH_PASSWORD=root
```

### 2. Verify Application is Running
```bash
curl http://localhost:8080/actuator/health
# Expected: {"status":"UP"}
```

## Authentication Setup

### Get JWT Token for Testing
```bash
# 1. Register a test user first
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "fullName": "Test User",
    "password": "TestPassword123"
  }'

# 2. Login and extract token
JWT_TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com", 
    "password": "TestPassword123"
  }' | jq -r '.token')

echo "JWT Token: $JWT_TOKEN"
```

---

## 🔐 AUTHENTICATION ENDPOINTS

### 1. User Registration
**Endpoint**: `POST /auth/register`  
**Authentication**: None  
**Description**: Register a new user account

```bash
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "newuser@example.com",
    "fullName": "New User",
    "password": "SecurePassword123"
  }'
```

**Expected Response (200)**:
```json
{
  "id": 1,
  "email": "newuser@example.com",
  "fullName": "New User",
  "emailVerified": false,
  "createdAt": "2025-07-23T10:00:00.000Z"
}
```

**Error Cases**:
```bash
# Duplicate email (409)
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "fullName": "Duplicate User", 
    "password": "password123"
  }'

# Invalid email format (400)
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "invalid-email",
    "fullName": "Invalid User",
    "password": "password123"
  }'

# Weak password (400)
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "weak@example.com",
    "fullName": "Weak Password User",
    "password": "123"
  }'
```

### 2. User Login
**Endpoint**: `POST /auth/login`  
**Authentication**: None  
**Description**: Authenticate user and receive JWT token

```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "TestPassword123"
  }'
```

**Expected Response (200)**:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": 1,
    "email": "testuser@example.com",
    "fullName": "Test User",
    "emailVerified": false
  },
  "expiresIn": 86400000
}
```

**Error Cases**:
```bash
# Wrong password (401)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "WrongPassword"
  }'

# Non-existent user (401)
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "nonexistent@example.com",
    "password": "password123"
  }'
```

### 3. Password Reset Request
**Endpoint**: `POST /auth/send-forgot-password`  
**Authentication**: None  
**Description**: Send password reset email

```bash
curl -X POST http://localhost:8080/auth/send-forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com"
  }'
```

**Expected Response (200)**:
```json
{
  "message": "Password reset email sent successfully",
  "email": "testuser@example.com"
}
```

### 4. Email Verification Check
**Endpoint**: `GET /users/email-exists`  
**Authentication**: None  
**Description**: Check if email exists in system

```bash
curl "http://localhost:8080/users/email-exists?email=testuser@example.com"
```

**Expected Response (200)**:
```json
{
  "exists": true,
  "email": "testuser@example.com"
}
```

---

## 👤 USER MANAGEMENT ENDPOINTS

### 1. Get Current User Profile
**Endpoint**: `GET /users/me`  
**Authentication**: JWT Bearer Token Required  
**Description**: Get authenticated user's profile

```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8080/users/me
```

**Expected Response (200)**:
```json
{
  "id": 1,
  "email": "testuser@example.com",
  "fullName": "Test User",
  "emailVerified": false,
  "createdAt": "2025-07-23T10:00:00.000Z",
  "updatedAt": "2025-07-23T10:00:00.000Z"
}
```

**Error Cases**:
```bash
# No token (401)
curl http://localhost:8080/users/me

# Invalid token (401)
curl -H "Authorization: Bearer invalid.token.here" \
  http://localhost:8080/users/me

# Expired token (401)
curl -H "Authorization: Bearer expired.jwt.token" \
  http://localhost:8080/users/me
```

### 2. Get All Users (Admin)
**Endpoint**: `GET /users`  
**Authentication**: JWT Bearer Token Required  
**Description**: Get paginated list of all users

```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8080/users
```

**With Pagination**:
```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  "http://localhost:8080/users?page=0&size=10"
```

**Expected Response (200)**:
```json
{
  "content": [
    {
      "id": 1,
      "email": "testuser@example.com",
      "fullName": "Test User",
      "emailVerified": false,
      "createdAt": "2025-07-23T10:00:00.000Z"
    }
  ],
  "totalElements": 1,
  "totalPages": 1,
  "size": 20,
  "number": 0
}
```

### 3. Get User by ID
**Endpoint**: `GET /users/{id}`  
**Authentication**: JWT Bearer Token Required  
**Description**: Get specific user by ID

```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8080/users/1
```

**Expected Response (200)**:
```json
{
  "id": 1,
  "email": "testuser@example.com",
  "fullName": "Test User",
  "emailVerified": false,
  "createdAt": "2025-07-23T10:00:00.000Z"
}
```

**Error Cases**:
```bash
# User not found (404)
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8080/users/999
```

---

## 🔑 JWKS ENDPOINTS

### 1. Get JSON Web Key Set
**Endpoint**: `GET /.well-known/jwks.json`  
**Authentication**: None  
**Description**: Get public keys for JWT verification

```bash
curl http://localhost:8080/.well-known/jwks.json
```

**Expected Response (200)**:
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
    },
    {
      "kty": "RSA",
      "use": "sig", 
      "alg": "RS256",
      "kid": "401E1A2E-0F55-455D-94B6-B05C82C2F25C",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256", 
      "kid": "502F3B4C-1234-5678-9ABC-DEF012345678",
      "n": "base64url-encoded-modulus",
      "e": "AQAB"
    }
  ]
}
```

### 2. JWKS Key Count Validation
```bash
# Count number of keys (should be 3)
curl -s http://localhost:8080/.well-known/jwks.json | jq '.keys | length'

# List all key IDs
curl -s http://localhost:8080/.well-known/jwks.json | jq -r '.keys[].kid'

# Validate key structure
curl -s http://localhost:8080/.well-known/jwks.json | jq '.keys[] | {kty, use, alg, kid}'
```

---

## 🏠 BASIC ENDPOINTS

### 1. Root Endpoint
**Endpoint**: `GET /`  
**Authentication**: None  
**Description**: Basic health check

```bash
curl http://localhost:8080/
```

**Expected Response (200)**:
```text
Hello, Welcome to OneAuth Service!
```

### 2. Application Health
**Endpoint**: `GET /actuator/health`  
**Authentication**: None  
**Description**: Spring Boot actuator health check

```bash
curl http://localhost:8080/actuator/health
```

**Expected Response (200)**:
```json
{
  "status": "UP"
}
```

### 3. Application Info
**Endpoint**: `GET /actuator/info`  
**Authentication**: None  
**Description**: Application information

```bash
curl http://localhost:8080/actuator/info
```

**Expected Response (200)**:
```json
{
  "app": {
    "name": "OneAuth-Service",
    "version": "0.0.1-SNAPSHOT"
  }
}
```

---

## 🔗 OAUTH2 ENDPOINTS (Social Login)

### 1. OAuth2 Authorization Endpoints
**Description**: Social login redirect URLs

```bash
# Google OAuth2
curl "http://localhost:8080/oauth2/authorization/google"
# Redirects to Google login

# Facebook OAuth2  
curl "http://localhost:8080/oauth2/authorization/facebook"
# Redirects to Facebook login

# GitHub OAuth2
curl "http://localhost:8080/oauth2/authorization/github"
# Redirects to GitHub login
```

### 2. OAuth2 Callback
**Endpoint**: `GET /oauth2/callback/{provider}`  
**Authentication**: OAuth2 Flow  
**Description**: OAuth2 callback handler

```bash
# These are handled by OAuth2 flow automatically
# /oauth2/callback/google
# /oauth2/callback/facebook
# /oauth2/callback/github
```

---

## 🧪 COMPREHENSIVE TESTING WORKFLOW

### Complete Authentication Flow Test
```bash
#!/bin/bash

BASE_URL="http://localhost:8080"
TEST_EMAIL="flowtest@example.com"
TEST_PASSWORD="FlowTest123"

echo "=== OneAuth App Complete Flow Test ==="

# 1. Health Check
echo "1. Testing health endpoint..."
curl -f $BASE_URL/actuator/health || echo "❌ Health check failed"

# 2. JWKS Endpoint
echo "2. Testing JWKS endpoint..."
KEYS_COUNT=$(curl -s $BASE_URL/.well-known/jwks.json | jq '.keys | length')
echo "   JWKS Keys: $KEYS_COUNT"

# 3. User Registration
echo "3. Testing user registration..."
curl -s -X POST $BASE_URL/auth/register \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"fullName\": \"Flow Test User\",
    \"password\": \"$TEST_PASSWORD\"
  }" > /dev/null

# 4. User Login
echo "4. Testing user login..."
LOGIN_RESPONSE=$(curl -s -X POST $BASE_URL/auth/login \
  -H "Content-Type: application/json" \
  -d "{
    \"email\": \"$TEST_EMAIL\",
    \"password\": \"$TEST_PASSWORD\"
  }")

TOKEN=$(echo $LOGIN_RESPONSE | jq -r '.token')
echo "   Token received: ${TOKEN:0:20}..."

# 5. Protected Endpoint Access
echo "5. Testing protected endpoint..."
USER_INFO=$(curl -s -H "Authorization: Bearer $TOKEN" $BASE_URL/users/me)
USER_EMAIL=$(echo $USER_INFO | jq -r '.email')
echo "   User email: $USER_EMAIL"

# 6. Error Case Testing
echo "6. Testing error cases..."

# Test without token (should get 401)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/users/me)
echo "   No token status: $STATUS (should be 401)"

# Test with invalid token (should get 401)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer invalid.token" $BASE_URL/users/me)
echo "   Invalid token status: $STATUS (should be 401)"

echo "=== Flow Test Complete ==="
```

### Performance Testing
```bash
# Response time testing
echo "=== Performance Testing ==="

# JWKS endpoint performance
echo "JWKS response time:"
time curl -s http://localhost:8080/.well-known/jwks.json > /dev/null

# Authentication performance  
echo "Login response time:"
time curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"TestPassword123"}' > /dev/null

# Concurrent requests test
echo "Concurrent JWKS requests (10 parallel):"
time (
  for i in {1..10}; do
    curl -s http://localhost:8080/.well-known/jwks.json > /dev/null &
  done
  wait
)
```

### Error Scenario Testing
```bash
echo "=== Error Scenario Testing ==="

# Test malformed JSON
echo "Testing malformed JSON:"
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"invalid":"json"'

# Test missing required fields
echo "Testing missing fields:"
curl -X POST http://localhost:8080/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test@test.com"}'

# Test invalid endpoints
echo "Testing 404 endpoints:"
curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/nonexistent

# Test wrong HTTP methods
echo "Testing wrong HTTP method:"
curl -s -o /dev/null -w "%{http_code}" -X DELETE http://localhost:8080/auth/login
```

---

## 📊 EXPECTED STATUS CODES

| Endpoint | Success | Error Cases |
|----------|---------|-------------|
| `POST /auth/register` | 200 | 400 (invalid data), 409 (duplicate email) |
| `POST /auth/login` | 200 | 401 (invalid credentials), 400 (malformed) |
| `GET /users/me` | 200 | 401 (unauthorized), 403 (forbidden) |
| `GET /users` | 200 | 401 (unauthorized) |
| `GET /users/{id}` | 200 | 401 (unauthorized), 404 (not found) |
| `GET /.well-known/jwks.json` | 200 | N/A (always accessible) |
| `GET /actuator/health` | 200 | 503 (service down) |
| `GET /` | 200 | N/A |

---

## 🔧 TROUBLESHOOTING

### Common Issues

#### 1. Database Connection Error
```bash
# Check MySQL is running
docker ps | grep mysql

# Test database connection
mysql -h localhost -u root -p -e "USE oneauth-db; SHOW TABLES;"
```

#### 2. JWT Token Issues
```bash
# Decode JWT token (first part)
echo "$JWT_TOKEN" | cut -d'.' -f1 | base64 -d

# Check token expiration
echo "$JWT_TOKEN" | cut -d'.' -f2 | base64 -d | jq '.exp'
```

#### 3. CORS Issues
```bash
# Test CORS with origin header
curl -H "Origin: http://localhost:3000" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: Content-Type" \
  -X OPTIONS http://localhost:8080/auth/login
```

#### 4. Port Conflicts
```bash
# Check what's using port 8080
lsof -ti:8080

# Kill processes on port 8080
lsof -ti:8080 | xargs kill -9
```

---

## 📝 NOTES

- **JWT Tokens**: Valid for 24 hours by default
- **Email Verification**: Currently optional in development mode
- **Rate Limiting**: Not implemented in current version
- **HTTPS**: Configure for production deployment
- **CORS**: Configured for development origins (localhost:3000, localhost:4200)
- **Database**: Uses MySQL with connection pooling
- **Logging**: Check application logs for detailed error information

This completes the comprehensive testing documentation for the OneAuth authentication server.