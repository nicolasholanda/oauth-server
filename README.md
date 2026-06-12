# OAuth 2.0 Server

A study implementation of an OAuth 2.0 Authorization Server in Java + Spring Boot, following [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749).

It is meant for learning and experimentation — not production use.

## Features

- Four grant types: `authorization_code`, `client_credentials`, `password`, `refresh_token`
- `authorization_code` flow with redirect handling
- JWT access tokens (HS256) and opaque refresh tokens
- Refresh token rotation with revocation of the previous pair
- Confidential and public clients
- Client authentication via HTTP Basic or form-encoded body
- Scope validation against the client's allowed scopes
- RFC-6749-compliant JSON error responses

## Tech Stack

- Java 21
- Spring Boot 3.4
- Spring Data JPA + H2 (PostgreSQL mode) + Flyway
- JJWT 0.12
- BCrypt (`spring-security-crypto`) for client and user secrets
- JUnit 5, Mockito, AssertJ, MockMvc

## Design Patterns

- **Strategy** — `GrantStrategy` interface with one implementation per grant type
- **Factory** — `GrantStrategyFactory` selects the right strategy based on `grant_type`
- **Repository** — Spring Data JPA repositories per aggregate
- Constructor injection throughout

## Package Layout

```
com.oauth.server
├── config        JwtProperties, SecurityConfig
├── controller    AuthorizationController, TokenController
├── domain
│   ├── entity    Client, User, Scope, AuthorizationCode, AccessToken, RefreshToken
│   └── enums     GrantType, ResponseType, TokenType, ClientType
├── dto
│   ├── request   AuthorizeRequest, TokenRequest
│   └── response  TokenResponse, ErrorResponse
├── exception     OAuth2Exception, OAuth2ErrorCode, GlobalExceptionHandler
├── repository    one per aggregate
└── service
    ├── generator TokenGenerator (JWT), CodeGenerator (opaque)
    └── strategy  GrantStrategy + 4 impls + GrantStrategyFactory
```

## Running

Requires Java 21 and Maven.

```
mvn spring-boot:run
```

The server starts on `http://localhost:8080`. An H2 in-memory database is created from Flyway migrations on startup. Configuration lives in `src/main/resources/application.yml`.

## Tests

```
mvn test
```

Unit tests live under `src/test/java/com/oauth/server/service/`. Integration tests (`*IT.java`) under `src/test/java/com/oauth/server/controller/` boot the full Spring context with MockMvc and the seeded H2 schema.

## Seeded Data

The Flyway seed migration (`V2__seed_data.sql`) creates everything needed to exercise the endpoints:

| Entity        | Identifier          | Notes                                                       |
|---------------|---------------------|-------------------------------------------------------------|
| Client        | `demo-client`       | Confidential, all four grants, secret = `secret`            |
| Client        | `public-client`     | Public, `authorization_code` + `refresh_token` only         |
| User          | `demo-user`         | Password = `secret`                                         |
| Scopes        | `read`, `write`, `openid`, `profile` | `demo-client` has all four; `public-client` has `read`, `openid`, `profile` |
| Redirect URI  | `http://localhost:3000/callback` | Registered for both clients                          |

The BCrypt hash `$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy` corresponds to the plaintext `secret` and is reused for both the demo client secret and the demo user password.

## Example Requests

### Authorization Code

This implementation does not ship a login UI — the `/oauth/authorize` endpoint accepts a `username` parameter to simulate the resource-owner authentication step.

```
curl -i -G http://localhost:8080/oauth/authorize \
  --data-urlencode "response_type=code" \
  --data-urlencode "client_id=demo-client" \
  --data-urlencode "redirect_uri=http://localhost:3000/callback" \
  --data-urlencode "scope=read write" \
  --data-urlencode "state=xyz123" \
  --data-urlencode "username=demo-user"
```

Response: `302 Found` with `Location: http://localhost:3000/callback?code=<CODE>&state=xyz123`.

Exchange the code for tokens:

```
curl -X POST http://localhost:8080/oauth/token \
  -u demo-client:secret \
  -d "grant_type=authorization_code" \
  -d "code=<CODE>" \
  -d "redirect_uri=http://localhost:3000/callback"
```

### Client Credentials

```
curl -X POST http://localhost:8080/oauth/token \
  -u demo-client:secret \
  -d "grant_type=client_credentials" \
  -d "scope=read"
```

### Password

```
curl -X POST http://localhost:8080/oauth/token \
  -u demo-client:secret \
  -d "grant_type=password" \
  -d "username=demo-user" \
  -d "password=secret" \
  -d "scope=read write"
```

### Refresh Token

```
curl -X POST http://localhost:8080/oauth/token \
  -u demo-client:secret \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<REFRESH_TOKEN>"
```

The previous access and refresh tokens are revoked; a fresh pair is returned.

## Token Response

```json
{
  "access_token": "<JWT>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque-string>",
  "scope": "read write"
}
```

Access tokens are signed JWTs containing `sub`, `iss`, `aud`, `client_id`, `scope`, and `token_type` claims.

## Error Response

```json
{
  "error": "invalid_grant",
  "error_description": "authorization code is expired or already used"
}
```

The `error` field matches one of the codes defined by RFC 6749 §5.2. The HTTP status reflects the error (`invalid_client` → 401, `access_denied` → 403, most others → 400).

## Notes

- HMAC secret and other settings are configurable via `oauth.*` properties in `application.yml`.
- This server intentionally omits a consent screen, PKCE, OpenID Connect, and resource-server protection — the focus is on the core RFC 6749 flows.
