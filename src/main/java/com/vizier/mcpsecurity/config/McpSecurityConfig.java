package com.vizier.mcpsecurity.config;

import org.springaicommunity.mcp.security.server.config.McpServerOAuth2Configurer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security for the MCP endpoint.
 *
 * <p>The MCP endpoint gets its own filter chain (ordered ahead of the default one in
 * {@link SecurityConfig}) configured with the community {@code mcp-security} module's
 * {@link McpServerOAuth2Configurer}. That configurer does two things the plain resource
 * server cannot: it advertises this server as an OAuth 2.0 protected resource
 * (RFC 9728 metadata at {@code /.well-known/oauth-protected-resource/mcp}) so MCP clients
 * can discover how to authenticate, and — critically — it propagates the authenticated
 * {@code SecurityContext} into MCP tool execution, which otherwise runs on a Reactor
 * worker thread where the thread-bound context would be lost. Per-tool scope enforcement
 * (the {@code @PreAuthorize} guards) is enabled separately by {@link MethodSecurityConfig}.
 *
 * <p>The endpoint itself requires authentication; the protected-resource metadata is
 * public so unauthenticated clients can discover the authorization server.
 *
 * <p>This chain performs OIDC discovery against the configured issuer when it is built, so
 * it needs a reachable authorization server. It is therefore excluded from the {@code test}
 * profile, under which the hermetic test suite verifies tool scope enforcement at the
 * method-security layer instead of over the network.
 */
@Configuration
@Profile("!test")
public class McpSecurityConfig {

	private final String issuerUri;

	public McpSecurityConfig(@Value("${mcp.security.oauth2.issuer-uri}") String issuerUri) {
		this.issuerUri = issuerUri;
	}

	@Bean
	@Order(1)
	SecurityFilterChain mcpSecurityFilterChain(HttpSecurity http) throws Exception {
		http
				.securityMatcher("/mcp", "/.well-known/oauth-protected-resource/**")
				.authorizeHttpRequests(authorize -> authorize
						// Metadata must be reachable without a token so clients can discover
						// the authorization server; the MCP endpoint itself requires auth.
						.requestMatchers("/.well-known/oauth-protected-resource/**").permitAll()
						.anyRequest().authenticated())
				// mcp-security: validates JWTs against the authorization server and bridges
				// the SecurityContext into tool execution. Issuer is externalized to config.
				.with(McpServerOAuth2Configurer.mcpServerOAuth2(), mcp -> mcp.authorizationServer(issuerUri))
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				.csrf(csrf -> csrf.disable());
		return http.build();
	}
}
