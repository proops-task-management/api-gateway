# api-gateway - Claude Agent

## Read these first (via Notion MCP)
- DOP-001: https://www.notion.so/3412ba48f4878140a5ebf3df60896b9b
- IRD-003: https://www.notion.so/3412ba48f487816080cfea3e82c02cdd

## Reference downstream contracts for routing only
- IRD-001: https://www.notion.so/3412ba48f48781be8364d68a02f8bafd
- IRD-002: https://www.notion.so/3412ba48f48781c89938c3078a3d09ec
- IRD-004: https://www.notion.so/3412ba48f48781bbaf85d69953a8fd07

---

## Scope
This repo contains api-gateway only.
Only implement what is defined in IRD-003 and the downstream API contracts it proxies. Nothing more.

The gateway owns:
- request routing
- JWT validation
- Redis blacklist checks
- injecting `X-User-Id` and `X-User-Role`
- direct `GET /health`
- gateway-owned JSON errors such as auth failures and unknown paths

The gateway does not own:
- user registration logic
- login logic
- task business rules
- notification business rules
- any database schema or persistence

---

## Auth & Observability (Production Program — D7, IRD-003 amended + ADR-005)

**JWT verification is RS256 verify-only (asymmetric), not HS256.**
- The gateway holds ONLY the **public key(s)** — `JWT_PUBLIC_KEYS` (PEM list, newest-first)
  replaces `JWT_SECRET`. It can verify user-service's tokens but **cannot sign** one, so a
  compromised gateway can never forge identities. No shared secret exists anymore.
- Key source: ESO secret backed by SSM `/proops/<env>/jwt/public_key` in k8s; an env var locally.
  `JwtUtil` parses each PEM once at startup via the JDK `KeyFactory` — no BouncyCastle.
- Multiple keys are accepted for 24 h dual-key rotation (IRD-019 runbook). Verification tries
  each key newest-first; the token's `kid` header (`proops-v1`) is preserved for the deferred
  full JWKS (ADR-005). The Redis blacklist-by-`jti` read path is **unchanged**.

**Actuator exposed** (allowlist `health,prometheus`):
- `/actuator/health/liveness` + `/actuator/health/readiness` — wired to k8s probes.
- `/actuator/prometheus` — the gateway is the system-wide RED source (IRD-020): per-route
  `http_server_requests`, URI-templated (`/tasks/{id}`, never raw IDs). Histogram buckets capped
  to the SLO set `100ms,300ms,1s,3s`. No auth (gateway is the upstream enforcer).

**Production hardening:** `server.shutdown=graceful` (20 s drain of in-flight proxied requests);
JVM `-XX:MaxRAMPercentage=75.0` set in the **Dockerfile** (`JAVA_TOOL_OPTIONS`), never in yaml;
downstream URLs are cluster DNS injected per env by the `app` chart; `CORS_ALLOWED_ORIGINS` per env.

**Build note:** Lombok is pinned on the `maven-compiler-plugin` `annotationProcessorPaths` (JDK 23+
disabled implicit classpath annotation-processing). Build with **Temurin 21**, never the host's
newer JDK — see `docs/troubleshooting/TSG-002`.

---

## NEVER
- Generate code for user-service, task-service, notification-service, or frontend-service
- Add routes that are not defined in DOP-001, IRD-003, or the referenced downstream contracts
- Use broad catch-all routes such as `/**`, `/tasks/**`, or `/notifications/**` that expose undeclared endpoints
- Own business data, create entities/repositories/migrations, or connect this repo to MySQL
- Issue/sign JWTs or call user-service at runtime to validate tokens - verify locally with the RS256 **public key(s)** in `JWT_PUBLIC_KEYS` only
- Trust client-supplied `X-User-Id` or `X-User-Role` headers - always remove and overwrite them from JWT claims before forwarding
- Enforce lead/member task rules, ownership rules, or notification ownership in the gateway - downstream services own business authorization
- Skip Redis blacklist checks on protected routes
- Write blacklist entries from the gateway - gateway only reads `blacklist:{jti}`
- Cache JWT validation results - verify signature and expiry on every protected request
- Rewrite downstream success or error bodies - proxy downstream responses unchanged
- Protect `POST /users`, `POST /auth/login`, or `GET /health`
- Leave any declared `/tasks` or `/notifications` route unprotected
- Hardcode secrets, ports, Redis hosts, or downstream URLs - all config comes from env vars
- Use Spring MVC controllers for proxied routes - use Spring Cloud Gateway route config plus filters
- Block the Netty event loop with direct blocking I/O inside a filter
- Log raw JWTs, `Authorization` headers, or secrets
- Use `@Autowired` for dependency injection - always use `@RequiredArgsConstructor` and `private final`
- Use `System.out.println` - always use `@Slf4j`
- Return HTML or Whitelabel errors - all gateway-owned errors must be JSON `{ "message": "..." }`
- Add CORS, rate limiting, retries, circuit breakers, service discovery, or API aggregation unless the IRD is updated

---

## Technology Stack

| Component | Choice | Why |
| --- | --- | --- |
| Language | Java 21 | Matches the platform baseline |
| Framework | Spring Boot 3 | Standard across services |
| Gateway | Spring Cloud Gateway | Reactive routing and filter chain |
| JWT validation | jjwt (**RS256 public-key verify**) | Verify-only — gateway holds no signing key (IRD-003 amended) |
| Blacklist store | Spring Data Redis | O(1) blacklist lookup by `jti` |
| Build tool | Maven | Standardized dependency management |

---

## Project Structure

```text
src/main/java/com/proops2026/gateway/
|-- filter/
|   `-- JwtAuthFilter.java        <- GlobalFilter implementation
|-- config/
|   `-- GatewayConfig.java
|-- util/
|   `-- JwtUtil.java
|-- exception/
|   `-- GlobalExceptionHandler.java
`-- ApiGatewayApplication.java
```

Notes:
- keep gateway code within this structure unless the IRD changes
- route declarations and direct gateway responses such as `GET /health` belong in `config/GatewayConfig.java`
- do not introduce `controller/`, `service/`, `dto/`, `repository/`, `entity/`, `mapper/`, `model/`, or `db/migrations/` packages in this repo

---

## Lombok and Class Conventions

**Filter**
```java
@Slf4j
@Component
@RequiredArgsConstructor
public class JwtAuthFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;
    private final StringRedisTemplate redisTemplate;
    private final ObjectMapper objectMapper;
}
```

**Utility**
```java
@Component
public class JwtUtil {
    public Claims parseAndValidate(String token) {
        // parse token, validate signature and expiry, then return claims
    }
}
```

**Exception handler**
```java
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handle(Exception ex) {
        return ResponseEntity.status(500).body(Map.of("message", ex.getMessage()));
    }
}
```

Rules:
- Do not use `@Data`
- Keep fields `private final` whenever possible
- Keep gateway helpers stateless
- Do not add support classes outside the structure above unless the spec changes

---

## Route Ownership Rules

**GatewayConfig** owns:
- explicit route definitions
- route IDs
- upstream URIs
- route metadata such as `authRequired`
- direct gateway responses such as `GET /health`
- unknown path handling

**JwtAuthFilter** owns:
- checking whether the matched route requires auth
- reading `Authorization: Bearer <token>`
- validating signature and expiry
- checking Redis blacklist by `jti`
- injecting `X-User-Id` and `X-User-Role`
- returning gateway-owned `401` JSON when auth fails
- one inbound request log line per request
- never logging tokens or secrets

**JwtUtil** owns:
- parsing JWT
- verifying signature and expiry
- exposing validated claims to the filter

**GlobalExceptionHandler** owns:
- mapping gateway-originated exceptions to JSON `{ "message": "..." }`
- never rewriting downstream proxied errors

---

## Route Table

| Method + Path | Upstream | Auth required |
| --- | --- | --- |
| `POST /users` | user-service | No |
| `POST /auth/login` | user-service | No |
| `GET /tasks` | task-service | Yes |
| `POST /tasks` | task-service | Yes |
| `GET /tasks/{id}` | task-service | Yes |
| `PATCH /tasks/{id}/assign` | task-service | Yes |
| `PATCH /tasks/{id}/status` | task-service | Yes |
| `PATCH /tasks/{id}/metadata` | task-service | Yes |
| `DELETE /tasks/{id}` | task-service | Yes |
| `POST /tasks/{id}/comments` | task-service | Yes |
| `GET /notifications` | notification-service | Yes |
| `PATCH /notifications/{id}/read` | notification-service | Yes |
| `GET /health` | gateway responds directly | No |
| any other path | gateway returns `404` | No |

Routing rules:
- define each route explicitly by method and path
- store `authRequired` as route metadata so auth behavior lives in one source of truth
- preserve path, query string, request body, and downstream status/body unchanged
- never proxy unknown paths to a downstream service

Example route style:
```java
@Bean
RouteLocator gatewayRoutes(RouteLocatorBuilder builder, GatewayProperties props) {
    return builder.routes()
        .route("users-register", r -> r
            .method(HttpMethod.POST)
            .and()
            .path("/users")
            .metadata("authRequired", false)
            .uri(props.getUserServiceUrl()))
        .route("tasks-list", r -> r
            .method(HttpMethod.GET)
            .and()
            .path("/tasks")
            .metadata("authRequired", true)
            .uri(props.getTaskServiceUrl()))
        .build();
}
```

---

## JWT Validation Contract

Protected routes follow this exact flow:

```text
1. Read Authorization header: "Bearer <token>"
2. If header missing or malformed -> 401 { "message": "authorization header required" }
3. Verify JWT signature with an RS256 public key from JWT_PUBLIC_KEYS (newest-first, kid preserved)
4. If signature invalid or token expired -> 401 { "message": "invalid or expired token" }
5. Extract claims: userId, email, role, jti
6. Check Redis key blacklist:{jti}
7. If key exists -> 401 { "message": "token has been revoked" }
8. Remove incoming X-User-Id and X-User-Role headers
9. Inject:
   X-User-Id: claims.userId
   X-User-Role: claims.role
10. Forward request to downstream service
```

Header mutation rule:
```java
ServerHttpRequest mutatedRequest = exchange.getRequest()
    .mutate()
    .headers(headers -> {
        headers.remove("X-User-Id");
        headers.remove("X-User-Role");
        headers.set("X-User-Id", claims.getUserId());
        headers.set("X-User-Role", claims.getRole());
    })
    .build();
```

Important:
- `JWT_PUBLIC_KEYS` must be the public half of user-service's `JWT_PRIVATE_KEY` (RS256)
- the gateway validates identity only
- the gateway does not decide whether a caller may assign a task, update metadata, or read a notification owned by someone else

---

## Redis Blacklist Rules

```text
key:   blacklist:{jti}
value: "revoked"
ttl:   remaining token lifetime
set by: user-service
read by: api-gateway
```

Rules:
- gateway only reads blacklist keys
- gateway checks blacklist on every protected request
- gateway does not maintain a second token state store
- if Redis access uses blocking APIs, move that call off the event loop

Recommended helper:
```java
private Mono<Boolean> isBlacklisted(String tokenId) {
    return Mono.fromCallable(() -> Boolean.TRUE.equals(
            redisTemplate.hasKey("blacklist:" + tokenId)))
        .subscribeOn(Schedulers.boundedElastic());
}
```

---

## Health and Not Found

**GET /health**
```json
{ "status": "ok", "service": "api-gateway" }
```

**Unknown path**
```json
{ "message": "not found" }
```

Rules:
- `GET /health` never requires auth
- unknown paths return gateway-owned `404`
- downstream `4xx` and `5xx` responses pass through unchanged

---

## Error Handling

Gateway-owned errors must use this JSON shape only:

```json
{ "message": "human-readable string" }
```

Exact auth messages:
- missing or malformed bearer token -> `"authorization header required"`
- invalid signature or expired token -> `"invalid or expired token"`
- blacklisted token -> `"token has been revoked"`

Rules:
- filter-level auth failures should be written directly to `ServerHttpResponse`
- never let filter failures fall back to HTML error pages
- `GlobalExceptionHandler` is only for gateway-originated exceptions, not for downstream service errors

Recommended helper:
```java
private Mono<Void> writeJson(ServerWebExchange exchange, HttpStatus status, String message) {
    exchange.getResponse().setStatusCode(status);
    exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
    byte[] body = objectMapper.writeValueAsBytes(Map.of("message", message));
    DataBuffer buffer = exchange.getResponse().bufferFactory().wrap(body);
    return exchange.getResponse().writeWith(Mono.just(buffer));
}
```

---

## Helper Rules

- If a block appears more than once, extract a private helper
- If a method exceeds 20 lines, split it
- Name helpers after what they do: `requiresAuth`, `extractBearerToken`, `mutateRequestWithClaims`, `writeUnauthorized`, `blacklistKey`
- Parse JWT in one place only
- Keep `JwtAuthFilter` thin by delegating JWT parsing and Redis access

---

## Naming Conventions

| Type | Pattern | Example |
| --- | --- | --- |
| Class | PascalCase | `JwtAuthFilter` |
| Method | camelCase, verb-first | `extractBearerToken` |
| Variable | camelCase | `mutatedRequest` |
| Constant | UPPER_SNAKE_CASE | `AUTH_REQUIRED_METADATA` |
| Filter | Noun + Filter | `JwtAuthFilter` |
| Util | Subject + Util | `JwtUtil` |
| Config | Subject + Config | `GatewayConfig` |
| Exception handler | Global + ExceptionHandler | `GlobalExceptionHandler` |

---

## Logging

Gateway logging must follow:

```java
log.info("[{}] {} {} -> {} ({}ms)", timestamp, method, path, status, durationMs);
```

Rules:
- log every inbound request once
- never log JWTs, `Authorization` headers, or `JWT_PUBLIC_KEYS`
- use `info` for request lifecycle, `warn` for rejected auth, `error` only for real gateway failures
- do not log downstream response bodies

---

## Testing

- Mock-based tests only
- Use `@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)` with `WebTestClient`
- Mock Redis blacklist lookups
- Mock downstream HTTP services with WireMock or MockWebServer
- No real MySQL, Redis, or downstream service is required in automated tests

Suggested test classes:
- `GatewayPublicRoutesTest`
- `GatewayProtectedRoutesTest`
- `JwtAuthFilterTest`
- `GlobalExceptionHandlerTest`

Suggested test methods:

```java
@Test
void postUsers_withoutAuthorization_proxiesToUserService() { }

@Test
void getTasks_missingAuthorization_returns401() { }

@Test
void getTasks_invalidToken_returns401() { }

@Test
void getTasks_revokedToken_returns401() { }

@Test
void getTasks_validToken_injectsHeadersAndForwards() { }

@Test
void getNotifications_validToken_routesToNotificationService() { }

@Test
void getHealth_returns200() { }

@Test
void unknownPath_returns404() { }
```

Minimum assertions:
- public routes do not require `Authorization`
- protected routes reject missing, invalid, and revoked tokens
- forwarded protected requests contain `X-User-Id` and `X-User-Role`
- unknown paths return `{ "message": "not found" }`
- downstream response body and status are not rewritten by the gateway

---

## Environment Variables

```text
PORT=8080
SPRING_CLOUD_GATEWAY_ROUTES_USER_SERVICE_URL=http://user-service:8081
SPRING_CLOUD_GATEWAY_ROUTES_TASK_SERVICE_URL=http://task-service:8082
SPRING_CLOUD_GATEWAY_ROUTES_NOTIFICATION_SERVICE_URL=http://notification-service:8083
JWT_PUBLIC_KEYS=-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----   # RS256 verify-only, newest-first list
SPRING_REDIS_HOST=redis
SPRING_REDIS_PORT=6379
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

Rules:
- `.env` is gitignored
- `.env.example` is committed
- never hardcode `JWT_PUBLIC_KEYS`
- `JWT_PUBLIC_KEYS` must be the public half of user-service's signing key (RS256, `kid=proops-v1`)

---

## Containerization

- Provide a `Dockerfile` for the gateway
- Expose port `8080` only
- Run the packaged jar in a non-root runtime image
- Do not scaffold sibling service folders in this repo just to satisfy stack-level Docker Compose

Gateway Dockerfile baseline:
```dockerfile
FROM maven:3.9-eclipse-temurin-21 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline
COPY src ./src
RUN mvn package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar
EXPOSE 8080
USER nobody
CMD ["java", "-jar", "app.jar"]
```
