package com.vizier.mcpsecurity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtIssuerValidator;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configures Spring Security as an OAuth 2.0 resource server for the MCP endpoints.
 *
 * <p>Implements capability #1 of the project and the OAuth 2.0 authorization section of
 * the MCP specification: MCP endpoints are protected behind Bearer-token (JWT) validation
 * (RFC 6749 §7, RFC 6750), JWT signatures are verified against a well-known JWKS endpoint
 * (RFC 7517), and a token is additionally checked for the expected issuer and audience
 * (RFC 7519).
 *
 * <p>Authorization is <strong>default-deny</strong>: every request must be authenticated
 * unless its path is in the explicit public allow-list. That way a newly added MCP tool
 * endpoint is protected the moment it exists — exposure is opt-in, protection is not.
 */
@Configuration
public class SecurityConfig {

	private final String jwkSetUri;
	private final String issuer;
	private final String audience;

	public SecurityConfig(
			@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri,
			@Value("${mcp.security.jwt.issuer}") String issuer,
			@Value("${mcp.security.jwt.audience}") String audience) {
		this.jwkSetUri = jwkSetUri;
		this.issuer = issuer;
		this.audience = audience;
	}

	/**
	 * Defines the default security filter chain: a stateless, default-deny resource server
	 * that authenticates requests with the configured {@link JwtDecoder}.
	 *
	 * <p>Ordered after the MCP chain (see {@code McpSecurityConfig}, order 1): the MCP
	 * endpoint is handled by that chain, and every other request falls through to this one.
	 */
	@Bean
	@Order(2)
	SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
		http
				.authorizeHttpRequests(authorize -> authorize
						// Public endpoints: liveness, and the OAuth metadata document added in
						// the discovery section. Everything else requires a valid token.
						.requestMatchers("/", "/actuator/health", "/.well-known/**").permitAll()
						.anyRequest().authenticated())
				// Validate incoming Bearer tokens as JWTs using our custom decoder.
				.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder)))
				// Bearer-token APIs are stateless: no server-side session is created or used.
				.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
				// No session cookies means no CSRF attack surface, so CSRF protection is off.
				.csrf(csrf -> csrf.disable());
		return http.build();
	}

	/**
	 * Builds the {@link JwtDecoder} used to validate Bearer tokens.
	 *
	 * <p>Signatures are verified against the JWKS endpoint (keys fetched lazily and
	 * cached). Beyond the signature we explicitly validate three things, because a valid
	 * signature alone does not make a token acceptable:
	 * <ul>
	 *   <li>{@code exp}/{@code nbf} — the token is currently within its validity window;</li>
	 *   <li>{@code iss} — the token came from the issuer we trust;</li>
	 *   <li>{@code aud} — the token was minted for this server (see {@link AudienceValidator}).</li>
	 * </ul>
	 * Defining this bean makes Spring Boot back off its auto-configured decoder so these
	 * validators take effect.
	 */
	@Bean
	JwtDecoder jwtDecoder() {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
		OAuth2TokenValidator<Jwt> validators = new DelegatingOAuth2TokenValidator<>(
				new JwtTimestampValidator(),
				new JwtIssuerValidator(issuer),
				new AudienceValidator(audience));
		decoder.setJwtValidator(validators);
		return decoder;
	}
}
