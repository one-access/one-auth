# Demo App 2 - API Testing Commands

Complete manual testing guide for Demo App 2 with curl commands for all endpoints and authentication scenarios.

## Application Overview

- **Application**: Demo App 2 (OneAuth Client Application)
- **Base URL**: `http://localhost:8082`
- **Port**: 8082
- **Application ID**: 0100
- **Purpose**: Demonstrates different JWT authentication patterns and authorization approaches

```bash
export AUTH_HOST="http://localhost:8080"
export DEMO_HOST="http://localhost:8082"
```

## Prerequisites

### 1. Start Demo App 2
```bash
cd demo-app2
mvn spring-boot:run \
  -DSERVER_PORT=8082 \
  -DDEMO2_SERVICE_IDENTITY_KID=BA8A7D28-F226-48F3-B064-535D3E5FF1F5 \
  -DDEMO2_SERVICE_IDENTITY_PRIVATE_KEY=<base64-private-key> \
  -DDEMO2_SERVICE_IDENTITY_PUBLIC_KEY=<base64-public-key>
```

### 2. Verify Application is Running
```bash
curl -i http://localhost:8082/actuator/health
```

## Token Setup

### Get User JWT Token (from OneAuth App)
```bash
# Ensure OneAuth App is running on port 8080
# Register and login to get user token
export JWT_TOKEN=$(curl -s -X POST ${AUTH_HOST}/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"test3@example.com","password":"password123"}' \
  | jq -r '.token')

echo "User JWT Token: $JWT_TOKEN"
```

```bash
curl -i -X POST $AUTH_HOST/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"test12@example.com","fullName":"Test User","password":"password123"}'
```

## 🌐 PUBLIC ENDPOINTS

### 1. Public Demo Endpoint
**Endpoint**: `GET /api/demo/public`  
**Authentication**: None  
**Description**: Publicly accessible endpoint without JWT

```bash
curl $DEMO_HOST/api/demo/public
```

### 2. Application Health
**Endpoint**: `GET /actuator/health`  
**Authentication**: None  
**Description**: Spring Boot actuator health check

```bash
curl $DEMO_HOST/actuator/health
```

### 3. Application Info
**Endpoint**: `GET /actuator/info`  
**Authentication**: None  
**Description**: Application information

```bash
curl -i $DEMO_HOST/actuator/info
```

---

## 👤 USER TOKEN ENDPOINTS

### 1. User Endpoint (Requires USER_TOKEN Authority)
**Endpoint**: `GET /api/demo/user`  
**Authentication**: JWT Bearer Token Required (User Token)  
**Description**: Requires valid user JWT with USER_TOKEN authority

```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  $DEMO_HOST/api/demo/user
```

**Error Cases**:
```bash
# No token (401)
curl http://localhost:8082/api/demo/user

# Invalid token (401)
curl -H "Authorization: Bearer invalid.token.here" \
  http://localhost:8082/api/demo/user
```

### 2. Admin Endpoint (Requires ADMIN Role)
**Endpoint**: `GET /api/demo/admin`  
**Authentication**: JWT Bearer Token Required (Admin Role)  
**Description**: Requires ADMIN role (typically service tokens)

```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8082/api/demo/admin
```

**Expected Response (403 for user token)**:
```json
{
  "error": "Forbidden",
  "message": "Access Denied"
}
```

### 3. Authentication Info Endpoint
**Endpoint**: `GET /api/demo/info`  
**Authentication**: JWT Bearer Token Required  
**Description**: Shows authentication details for debugging

```bash
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8082/api/demo/info
```

**Expected Response (200)**:
```text
Authentication info - Principal: testuser@example.com, Type: JwtAuthenticationToken, Authorities: [USER_TOKEN]
```

---

## 🔧 SERVICE TOKEN ENDPOINTS

### 1. Service Endpoint (Filter Validation)
**Endpoint**: `GET /api/demo/service`  
**Authentication**: Service Token in X-Service-Token Header  
**Description**: Requires service JWT, validated by filter

```bash
export SERVICE_TOKEN="eyJraWQiOiJCQThBN0QyOC1GMjI2LTQ4RjMtQjA2NC01MzVEM0U1RkYxRjUiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIiLCJpc3MiOiJhdXRoLXNlcnZlciIsImlhdCI6MTc1MzQxNjI2OCwiZXhwIjoxNzUzNDE5ODY4LCJ0b2tlbl90eXBlIjoic2VydmljZSJ9.Rocx-Z6XKQK4Sswf0khCnb9j9v8CUp25L95XU0DaEsKWzBshFgfZNVIZR9GkGgDp24G-v0UquHkMJN_3gqc-HCtAPdSCBFN99Fe0pmBExQdcMQcyGqoTt0i-ZZk4nc3YVJiL0s4jvMrUc1BG7boE6AYnB11D3PVR6SkcSjmI2bWqXqgSxEqsImLUKDXVKMVscGBHpnbJAVpHoiJLw7AVuU6YnIJYmTe3R9vf-te6NZsahiNkK9VmBMzTznwtvg7cBEkSUxdmoZn-Y9_JeijrGqL6sHifkMU5bPiv8Eng-1URg5q-p3OOvf8aIHtWqrAhFjJy1t7ggPrpNs8sLD4zaA"

```
```bash
curl -i -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/demo/service
```

**Expected Response (200)**:
```text
Service endpoint - requires service JWT (X-Service-Token). Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

### 2. Service Endpoint (With @PreAuthorize)
**Endpoint**: `GET /api/demo/service-with-preauth`  
**Authentication**: Service Token in X-Service-Token Header  
**Description**: Requires service JWT with @PreAuthorize check

```bash
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/demo/service-with-preauth
```

**Expected Response (200)**:
```text
Service endpoint with @PreAuthorize - requires service JWT. Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

### 3. Universal Access Service Endpoint
**Endpoint**: `GET /api/demo/admin/universal`  
**Authentication**: Service Token in X-Service-Token Header  
**Description**: Any valid service token can access

```bash
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/demo/admin/universal
```

**Expected Response (200)**:
```text
Universal access endpoint - any valid service token can access. Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

### 4. App-Specific Endpoint
**Endpoint**: `GET /api/demo/payments/app-specific`  
**Authentication**: Service Token in X-Service-Token Header  
**Description**: Only specific apps with specific scopes can access

```bash
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/demo/payments/app-specific
```

**Expected Response (200)**:
```text
App-specific endpoint - only specific apps with specific scopes can access. Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

---

## 🔄 HYBRID TOKEN ENDPOINTS

### 1. Hybrid Endpoint (User OR Service Token)
**Endpoint**: `GET /api/demo/hybrid`  
**Authentication**: User Token OR Service Token  
**Description**: Accepts either user JWT or service JWT

```bash
# Test with user token
curl -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8082/api/demo/hybrid

# Test with service token
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/demo/hybrid
```

**Expected Response (200) with User Token**:
```text
Hybrid endpoint - accepts user OR service JWT. Principal: testuser@example.com, Authorities: [USER_TOKEN]
```

**Expected Response (200) with Service Token**:
```text
Hybrid endpoint - accepts user OR service JWT. Principal: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

### 2. Both Tokens Required Endpoint
**Endpoint**: `GET /api/demo/both-required`  
**Authentication**: Both User Token AND Service Token  
**Description**: Requires both user JWT and service JWT (impossible scenario)

```bash
# This will fail as it's impossible to have both token types simultaneously
curl -H "Authorization: Bearer $JWT_TOKEN" \
  -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/demo/both-required
```

**Expected Response (403)**:
```json
{
  "error": "Forbidden",
  "message": "Access Denied"
}
```

---

## 🎯 SCOPED SERVICE ENDPOINTS

### 1. Payment Write Endpoint
**Endpoint**: `GET /api/services/payments/write`  
**Authentication**: Service Token with PAYMENT_SERVICE_WRITE scope  
**Description**: Requires specific payment service with WRITE scope

```bash
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/services/payments/write
```

**Expected Response (200)**:
```text
Payment write endpoint - requires payment-service with WRITE scope. Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

### 2. Payment Read Endpoint
**Endpoint**: `GET /api/services/payments/read`  
**Authentication**: Service Token with PAYMENT_SERVICE_READ or ADMIN_SERVICE_READ scope  
**Description**: Requires payment or admin service with READ scope

```bash
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/services/payments/read
```

**Expected Response (200)**:
```text
Payment read endpoint - requires payment-service or admin-service with READ scope. Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

### 3. All Services Endpoint
**Endpoint**: `GET /api/services/all-services`  
**Authentication**: Service Token with ROLE_SERVICE  
**Description**: Any valid service token can access

```bash
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/services/all-services
```

**Expected Response (200)**:
```text
READ-only for all services endpoint - any valid service token can access with read scope. Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

### 4. Read-Only with PreAuth
**Endpoint**: `GET /api/services/readonly/with-preauth`  
**Authentication**: Service Token with READ scope  
**Description**: Requires service token with read scope using @PreAuthorize

```bash
curl -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/services/readonly/with-preauth
```

**Expected Response (200)**:
```text
READ-only with @PreAuthorize - requires service token with read scope. Service: 0100_DEMO3, Authorities: [SERVICE_TOKEN, SERVICE_APP_0100_DEMO3_READ, SERVICE_APP_0100_DEMO3_WRITE]
```

---

## 🧪 COMPREHENSIVE TESTING WORKFLOW

### Complete Flow Test
```bash
#!/bin/bash

BASE_URL="http://localhost:8082"
AUTH_URL="http://localhost:8080"
JAR_URL="http://localhost:8081"

echo "=== Demo App 2 Complete Flow Test ==="

# 1. Health Check
echo "1. Testing health endpoint..."
curl -f $BASE_URL/actuator/health || echo "❌ Health check failed"

# 2. Public Endpoint
echo "2. Testing public endpoint..."
PUBLIC_RESPONSE=$(curl -s $BASE_URL/api/demo/public)
echo "   Response: $PUBLIC_RESPONSE"

# 3. Get User Token
echo "3. Getting user JWT token..."
JWT_TOKEN=$(curl -s -X POST $AUTH_URL/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"testuser@example.com","password":"TestPassword123"}' \
  | jq -r '.token')
echo "   User token: ${JWT_TOKEN:0:20}..."

# 4. Get Service Token
echo "4. Getting service JWT token..."
SERVICE_TOKEN=$(curl -s -X POST $JAR_URL/api/service-auth/generate-token \
  -H "Content-Type: application/json" \
  -d '{"appId":"0100_DEMO3","scopes":["READ","WRITE"]}' \
  | jq -r '.token')
echo "   Service token: ${SERVICE_TOKEN:0:20}..."

# 5. Test User Endpoint
echo "5. Testing user endpoint..."
USER_RESPONSE=$(curl -s -H "Authorization: Bearer $JWT_TOKEN" $BASE_URL/api/demo/user)
echo "   Response: $USER_RESPONSE"

# 6. Test Service Endpoint
echo "6. Testing service endpoint..."
SERVICE_RESPONSE=$(curl -s -H "X-Service-Token: $SERVICE_TOKEN" $BASE_URL/api/demo/service)
echo "   Response: $SERVICE_RESPONSE"

# 7. Test Hybrid Endpoint
echo "7. Testing hybrid endpoint with user token..."
HYBRID_USER=$(curl -s -H "Authorization: Bearer $JWT_TOKEN" $BASE_URL/api/demo/hybrid)
echo "   User response: $HYBRID_USER"

echo "8. Testing hybrid endpoint with service token..."
HYBRID_SERVICE=$(curl -s -H "X-Service-Token: $SERVICE_TOKEN" $BASE_URL/api/demo/hybrid)
echo "   Service response: $HYBRID_SERVICE"

# 9. Test Scoped Endpoints
echo "9. Testing scoped payment endpoints..."
PAYMENT_WRITE=$(curl -s -H "X-Service-Token: $SERVICE_TOKEN" $BASE_URL/api/services/payments/write)
echo "   Payment write: $PAYMENT_WRITE"

PAYMENT_READ=$(curl -s -H "X-Service-Token: $SERVICE_TOKEN" $BASE_URL/api/services/payments/read)
echo "   Payment read: $PAYMENT_READ"

# 10. Error Case Testing
echo "10. Testing error cases..."

# Test without token (should get 401)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" $BASE_URL/api/demo/user)
echo "    No token status: $STATUS (should be 401)"

# Test admin endpoint with user token (should get 403)
STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $JWT_TOKEN" $BASE_URL/api/demo/admin)
echo "    Admin with user token: $STATUS (should be 403)"

echo "=== Demo App 2 Flow Test Complete ==="
```

### Performance Testing
```bash
echo "=== Demo App 2 Performance Testing ==="

# Public endpoint performance
echo "Public endpoint response time:"
time curl -s http://localhost:8082/api/demo/public > /dev/null

# User endpoint performance
echo "User endpoint response time:"
time curl -s -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8082/api/demo/user > /dev/null

# Service endpoint performance
echo "Service endpoint response time:"
time curl -s -H "X-Service-Token: $SERVICE_TOKEN" \
  http://localhost:8082/api/demo/service > /dev/null

# Concurrent requests test
echo "Concurrent requests (10 parallel):"
time (
  for i in {1..10}; do
    curl -s http://localhost:8082/api/demo/public > /dev/null &
  done
  wait
)
```

### Authorization Matrix Testing
```bash
echo "=== Authorization Matrix Testing ==="

# Test all endpoints with different token types
ENDPOINTS=(
  "/api/demo/public"
  "/api/demo/user"
  "/api/demo/admin"
  "/api/demo/service"
  "/api/demo/hybrid"
  "/api/services/payments/write"
  "/api/services/payments/read"
)

echo "Testing with no token:"
for endpoint in "${ENDPOINTS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:8082$endpoint")
  echo "  $endpoint: $status"
done

echo "Testing with user token:"
for endpoint in "${ENDPOINTS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Bearer $JWT_TOKEN" "http://localhost:8082$endpoint")
  echo "  $endpoint: $status"
done

echo "Testing with service token:"
for endpoint in "${ENDPOINTS[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "X-Service-Token: $SERVICE_TOKEN" "http://localhost:8082$endpoint")
  echo "  $endpoint: $status"
done
```

---

## 📊 EXPECTED STATUS CODES

| Endpoint | No Token | User Token | Service Token | Notes |
|----------|----------|------------|---------------|-------|
| `GET /api/demo/public` | 200 | 200 | 200 | Always accessible |
| `GET /api/demo/user` | 401 | 200 | 401 | Requires USER_TOKEN |
| `GET /api/demo/admin` | 401 | 403 | 200* | Requires ADMIN role |
| `GET /api/demo/service` | 401 | 401 | 200 | Requires service JWT |
| `GET /api/demo/hybrid` | 401 | 200 | 200 | Accepts either token |
| `GET /api/demo/both-required` | 401 | 403 | 403 | Impossible scenario |
| `GET /api/services/payments/write` | 401 | 403 | 200 | Requires service with WRITE |
| `GET /api/services/payments/read` | 401 | 403 | 200 | Requires service with READ |

*Service tokens typically have ADMIN role

---

## 🔧 TROUBLESHOOTING

### Common Issues

#### 1. Application Won't Start
```bash
# Check port availability
lsof -ti:8082

# Check environment variables
echo $DEMO2_SERVICE_IDENTITY_KID
echo $DEMO2_SERVICE_IDENTITY_PRIVATE_KEY
```

#### 2. JWT Token Issues
```bash
# Decode JWT token header
echo "$JWT_TOKEN" | cut -d'.' -f1 | base64 -d | jq

# Check token expiration
echo "$JWT_TOKEN" | cut -d'.' -f2 | base64 -d | jq '.exp'

# Verify token signature matches expected kid
echo "$JWT_TOKEN" | cut -d'.' -f1 | base64 -d | jq '.kid'
```

#### 3. Service Token Issues
```bash
# Verify service token scopes
echo "$SERVICE_TOKEN" | cut -d'.' -f2 | base64 -d | jq '.scopes'

# Check app ID
echo "$SERVICE_TOKEN" | cut -d'.' -f2 | base64 -d | jq '.sub'
```

#### 4. Authorization Issues
```bash
# Check security logs
tail -f /var/log/oneaccess/one-auth.log | grep -i "access denied"

# Test with curl verbose mode
curl -v -H "Authorization: Bearer $JWT_TOKEN" \
  http://localhost:8082/api/demo/user
```

---

## 📝 NOTES

- **User Tokens**: Use Authorization header with Bearer prefix
- **Service Tokens**: Use X-Service-Token header (no Bearer prefix)
- **Public Endpoints**: No authentication required
- **Hybrid Endpoints**: Accept either user or service tokens
- **Scoped Endpoints**: Require specific service permissions
- **Error Responses**: 401 (unauthorized), 403 (forbidden), 404 (not found)
- **Logging**: Debug level enabled for Spring Security and Web
- **Configuration**: Service patterns defined in application.yml

This completes the comprehensive testing documentation for Demo App 2.