# Token exchange flow (RFC 8693)

How an authenticated identity travels to a downstream service without credential re-entry.
The MCP server exchanges the caller's JWT for a token scoped to "service B", preserving the
original user identity (cascading delegation).

```mermaid
sequenceDiagram
    autonumber
    participant Client as MCP Client
    participant MCP as MCP Server
    participant AS as Authorization Server
    participant B as Service B (downstream)

    Client->>MCP: POST /mcp tools/call (Bearer user-JWT)
    MCP->>MCP: Validate JWT, authorize, resolve tenant
    Note over MCP: Tool needs to call Service B as the user

    MCP->>AS: POST /token<br/>grant_type=urn:ietf:params:oauth:grant-type:token-exchange<br/>subject_token=user-JWT, subject_token_type=jwt<br/>audience=service-b
    AS-->>MCP: 200 exchanged token { sub preserved, aud: service-b }

    MCP->>B: Request (Bearer exchanged-token)
    B->>B: Validate token (issuer, aud=service-b, scope)
    B-->>MCP: 200 result
    MCP-->>Client: 200 result
```

Notes:

- The caller's JWT is sent as the **`subject_token`**; the authorization server mints a new
  token whose `sub` still identifies the original user — delegation, not impersonation.
- Spring does not send an `audience` on a token exchange by default; this server adds it so
  Service B's resource server accepts the token (`aud = service-b`).
- The exchange is performed by `TokenExchangeService` using Spring Security's
  `TokenExchangeOAuth2AuthorizedClientProvider`; no user credentials are re-entered.
