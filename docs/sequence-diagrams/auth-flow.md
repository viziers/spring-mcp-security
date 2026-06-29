# Authentication flow

How an MCP client discovers the authorization server, obtains a token, and makes an
authenticated, scope-checked, tenant-scoped tool call against this server.

```mermaid
sequenceDiagram
    autonumber
    participant Client as MCP Client
    participant MCP as MCP Server (resource server)
    participant AS as Authorization Server

    Note over Client,MCP: Discovery
    Client->>MCP: POST /mcp (no token)
    MCP-->>Client: 401 Unauthorized<br/>WWW-Authenticate: Bearer resource_metadata="…/oauth-protected-resource/mcp"
    Client->>MCP: GET /.well-known/oauth-protected-resource/mcp
    MCP-->>Client: 200 Protected Resource Metadata (RFC 9728)<br/>authorization_servers: [issuer]
    Client->>AS: GET /.well-known/openid-configuration
    AS-->>Client: 200 token_endpoint, jwks_uri, …

    Note over Client,AS: Token acquisition
    Client->>AS: POST /token (client_credentials, scope=mcp:read)
    AS-->>Client: 200 JWT { sub, tenant_id, scope: mcp:read, aud: mcp-server }

    Note over Client,MCP: Authenticated tool call
    Client->>MCP: POST /mcp tools/call readExample(id) (Bearer JWT)
    MCP->>MCP: Verify JWT signature (JWKS), issuer, audience
    MCP->>MCP: @PreAuthorize hasAuthority(SCOPE_mcp:read)
    MCP->>MCP: Resolve tenant from tenant_id claim
    MCP->>MCP: Audit invocation (identity, tenant, tool, params, outcome)
    MCP-->>Client: 200 result (scoped to the caller's tenant)
```

Notes:

- The MCP server publishes **two** discovery documents (the spec changed mid-revision):
  Protected Resource Metadata (RFC 9728) at `/.well-known/oauth-protected-resource/mcp`,
  and Authorization Server Metadata (RFC 8414) at `/.well-known/oauth-authorization-server`.
- Signature validity alone is not sufficient — the server also checks `iss` and `aud`.
- Authorization is per tool (`@PreAuthorize` on the scope) and per tenant (the `tenant_id`
  claim scopes all data access); both rely on the `SecurityContext` being propagated into
  the tool's worker thread.
- A token carrying only `mcp:read` is denied the write tool.
