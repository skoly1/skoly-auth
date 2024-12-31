# Register
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

# Login
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "password123"}'

# Refresh Token
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "your-refresh-token"}'

# Get User Info (Protected)
curl -X GET http://localhost:3000/auth/me \
  -H "Authorization: Bearer your-access-token"

# Start Email Verification
curl -X POST http://localhost:3000/auth/verify/start \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com"}'

# Complete Email Verification
curl -X POST http://localhost:3000/auth/verify/complete \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "token": "your-verification-token"}'

# Health Check
curl -X GET http://localhost:3000/health

# Access Protected Route
curl -X GET http://localhost:3000/api/protected \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJlbWFpbCI6InRlc3RAZXhhbXBsZS5jb20iLCJ0eXBlIjoiYWNjZXNzIiwic3ViIjoiNDc0MzE2ODEtYjFhMC00MDQyLTgyODYtYjljNzc4MjM1Nzc1IiwiaWF0IjoxNzM1NTg0NjY3LCJleHAiOjE3MzU1ODU1Njd9.ldcegwbRUi0QXor_3HifIbZ_StFhM6L4im6e1QhMMMc"




DROP TABLE IF EXISTS auth_refresh_tokens CASCADE;
DROP TABLE IF EXISTS auth_verification_tokens CASCADE;
DROP TABLE IF EXISTS auth_sessions CASCADE;
DROP TABLE IF EXISTS auth_credentials CASCADE;
DROP TABLE IF EXISTS users CASCADE;

sk-9b4c38d7bbc84629a144d6b135d86b7f