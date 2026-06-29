package com.vizier.mcpsecurity.wellknown;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes an OAuth 2.0 Authorization Server Metadata document (RFC 8414) at
 * {@code /.well-known/oauth-authorization-server}, so MCP clients can discover the
 * authorization server's endpoints programmatically rather than hardcoding them. This is
 * the discovery mechanism described by the MCP specification (2025-03-26).
 *
 * <p>The document is built from externalized {@code mcp.discovery.*} configuration; it does
 * not validate against the live authorization server, so its values must be configured to
 * match it. The endpoint is public (no token required).
 *
 * <p>Note: newer MCP revisions and the {@code mcp-security} module instead use Protected
 * Resource Metadata (RFC 9728), already published at
 * {@code /.well-known/oauth-protected-resource/mcp}. Both documents are present so the
 * reference shows how MCP auth discovery evolved.
 */
@RestController
public class AuthorizationServerMetadataController {

	private final String issuer;
	private final String authorizationEndpoint;
	private final String tokenEndpoint;
	private final String jwksUri;
	private final List<String> scopesSupported;

	public AuthorizationServerMetadataController(
			@Value("${mcp.discovery.issuer}") String issuer,
			@Value("${mcp.discovery.authorization-endpoint}") String authorizationEndpoint,
			@Value("${mcp.discovery.token-endpoint}") String tokenEndpoint,
			@Value("${mcp.discovery.jwks-uri}") String jwksUri,
			@Value("${mcp.discovery.scopes-supported}") List<String> scopesSupported) {
		this.issuer = issuer;
		this.authorizationEndpoint = authorizationEndpoint;
		this.tokenEndpoint = tokenEndpoint;
		this.jwksUri = jwksUri;
		this.scopesSupported = scopesSupported;
	}

	@GetMapping(path = "/.well-known/oauth-authorization-server", produces = MediaType.APPLICATION_JSON_VALUE)
	public Map<String, Object> authorizationServerMetadata() {
		// RFC 8414 metadata. Keys are snake_case per the spec; insertion order is preserved
		// for a stable, readable document.
		Map<String, Object> metadata = new LinkedHashMap<>();
		metadata.put("issuer", this.issuer);
		metadata.put("authorization_endpoint", this.authorizationEndpoint);
		metadata.put("token_endpoint", this.tokenEndpoint);
		metadata.put("jwks_uri", this.jwksUri);
		metadata.put("scopes_supported", this.scopesSupported);
		metadata.put("response_types_supported", List.of("code"));
		metadata.put("grant_types_supported", List.of(
				"authorization_code",
				"client_credentials",
				"urn:ietf:params:oauth:grant-type:token-exchange"));
		metadata.put("token_endpoint_auth_methods_supported", List.of(
				"client_secret_basic",
				"client_secret_post"));
		return metadata;
	}
}
