# spring-mcp-security

A reference implementation showing how to secure [Model Context Protocol](https://modelcontextprotocol.io)
(MCP) servers with **Spring Boot** and **Spring Security**.

This is not a framework or a library. It is a working, runnable example that a Spring
Boot developer can read, understand, and adapt to their own stack with confidence.

> **Status: early development.** The repository is being built capability by
> capability. See [Roadmap](#roadmap) for what is implemented today.

---

## Why this exists

Three things recently became true at the same time:

- Spring AI's MCP server support is new.
- The MCP specification added an OAuth 2.0 authorization section.
- No clean reference exists showing how these connect using Spring Security as the
  auth layer.

This project is that reference. Every implementation decision traces back to a
published standard, and where a decision is not spec-mandated, it is documented as an
architectural choice with reasoning (see [Architecture Decision Records](#architecture-decision-records)).

---

## What it demonstrates

1. **OAuth 2.0 resource server config for MCP endpoints** — Spring Security as an
   OAuth 2.0 resource server, MCP tool endpoints behind Bearer token validation, JWT
   signature verification against a well-known JWKS endpoint.
2. **Tool-level scope enforcement** — individual MCP tools require specific OAuth
   scopes, enforced at the Spring Security method level rather than in application
   logic. Tools self-document their required scopes.
3. **RFC 8693 token exchange** — cascading delegation: a token valid at service A is
   exchanged for a token valid at service B while preserving the original user
   identity, so authenticated context travels across MCP boundaries without
   credential re-entry.
4. **Multi-tenant isolation** — tool calls are scoped to the authenticated tenant,
   extracted from JWT claims; one tenant cannot reach another's data through a shared
   server.
5. **Audit logging** — every tool invocation logged (identity, tenant, tool, sanitized
   inputs, outcome, timestamp) via a Spring AOP interceptor, emitted as structured JSON.
6. **`/.well-known` discovery** — a standards-compliant OAuth authorization server
   metadata document so MCP clients can discover auth endpoints programmatically.

---

## Standards implemented

- [MCP Specification (2025-03-26)](https://modelcontextprotocol.io/specification) — OAuth 2.0 authorization section
- [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749) — OAuth 2.0 Authorization Framework
- [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693) — OAuth 2.0 Token Exchange
- [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) — JSON Web Token (JWT)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)

---

## Technology stack

| Component    | Choice                                    | Reason                                          |
|--------------|-------------------------------------------|-------------------------------------------------|
| Runtime      | Java 21                                   | LTS, virtual threads available                  |
| Framework    | Spring Boot 3.x                           | Production standard, Spring Security integration |
| MCP          | Spring AI MCP Server                       | Official Spring MCP support                      |
| Auth         | Spring Security OAuth2 Resource Server     | Battle tested, spec compliant                    |
| Token format | JWT (RS256)                               | Stateless, verifiable, standard                  |
| Build        | Gradle                                     | Standard Spring Boot tooling                     |
| Test         | JUnit 5 + Spring Boot Test                 | Standard Spring testing stack                    |

---

## Roadmap

Built one capability at a time; each is complete only when its tests pass.

- [x] 1. OAuth 2.0 resource server configuration
- [x] 2. Tool-level scope enforcement
- [x] 3. RFC 8693 token exchange
- [ ] 4. Multi-tenant isolation
- [ ] 5. Audit logging via AOP
- [ ] 6. `/.well-known` discovery document

---

## Running locally

The MCP endpoint is a secured OAuth 2.0 resource that performs OIDC discovery at startup,
so it needs an authorization server. A preconfigured one is provided via Docker.

**Prerequisites:** Java 21+ (or just the Gradle wrapper — it self-provisions the JDK),
Docker, and Docker Compose.

**1. Start the authorization server** (Keycloak, realm `mcp`, on `http://localhost:8081`):

```bash
docker compose up -d
```

It exposes the issuer at `http://localhost:8081/realms/mcp` with `mcp:read` / `mcp:write`
scopes and a confidential client `mcp-client` (secret `mcp-secret`). These are throwaway
local-development credentials only.

**2. Run the application** (listens on `http://localhost:8082`):

```bash
export MCP_OAUTH2_ISSUER_URI=http://localhost:8081/realms/mcp
export MCP_JWT_ISSUER=http://localhost:8081/realms/mcp
export MCP_JWT_JWK_SET_URI=http://localhost:8081/realms/mcp/protocol/openid-connect/certs

./gradlew bootRun
```

**3. Get an access token** with the scopes you want (request `mcp:read`, `mcp:write`, or both):

```bash
curl -s -X POST http://localhost:8081/realms/mcp/protocol/openid-connect/token \
  -d grant_type=client_credentials \
  -d client_id=mcp-client -d client_secret=mcp-secret \
  -d 'scope=mcp:read mcp:write' | jq -r .access_token
```

**4. Call the MCP server.** The Streamable-HTTP MCP endpoint is `http://localhost:8082/mcp`
and requires `Authorization: Bearer <token>`. The OAuth protected-resource metadata
(RFC 9728) is published at `http://localhost:8082/.well-known/oauth-protected-resource/mcp`.
Point an MCP client (e.g. the MCP Inspector) at the endpoint with the bearer token; a token
carrying only `mcp:read` can invoke the read tool but is denied the write tool.

> **Ports:** app `8082`, Keycloak `8081`. Override the app port with `MCP_SERVER_PORT`.
> Stop the auth server with `docker compose down`.

---

## Scope

**This project is the resource-server side only.** It deliberately does not include:

- A published Maven/Gradle artifact — copy the patterns, don't take a dependency.
- Support for non-Spring stacks.
- A full authorization server — use [Keycloak](https://www.keycloak.org/),
  [Auth0](https://auth0.com/), or
  [Spring Authorization Server](https://spring.io/projects/spring-authorization-server).
- Production-ready configuration — environment-specific config, secrets management,
  and deployment are out of scope and noted where they apply.

---

## License

[MIT](LICENSE) © 2026 Vizier

---

*Vizier — AI Systems Architecture*
