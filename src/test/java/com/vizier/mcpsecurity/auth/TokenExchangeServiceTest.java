package com.vizier.mcpsecurity.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.time.Instant;

import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Verifies {@link TokenExchangeService} performs a correct RFC 8693 exchange: a well-formed
 * request carrying the caller's JWT as the subject token, and the exchanged token returned.
 *
 * <p>The authorization server's token endpoint is stood in for by a {@link MockWebServer},
 * so no live server is needed. The exchanged token's {@code sub} preservation is the
 * authorization server's responsibility; what we assert here is that we hand it the caller's
 * identity (the {@code subject_token}) correctly.
 */
@SpringBootTest
@ActiveProfiles("test")
class TokenExchangeServiceTest {

	private static final String CALLER_TOKEN_VALUE = "caller-jwt-token-value";

	private static MockWebServer authServer;

	@Autowired
	private TokenExchangeService tokenExchangeService;

	@DynamicPropertySource
	static void tokenEndpoint(DynamicPropertyRegistry registry) throws IOException {
		authServer = new MockWebServer();
		authServer.start();
		registry.add("spring.security.oauth2.client.provider.downstream-auth-server.token-uri",
				() -> authServer.url("/oauth2/token").toString());
	}

	@AfterAll
	static void shutDown() throws IOException {
		authServer.shutdown();
	}

	@Test
	void exchangesCallerJwtForDownstreamToken() throws InterruptedException {
		authServer.enqueue(new MockResponse()
				.setResponseCode(200)
				.setHeader("Content-Type", "application/json")
				.setBody("""
						{
						  "access_token": "exchanged-token-for-service-b",
						  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
						  "token_type": "Bearer",
						  "expires_in": 3600,
						  "scope": "service-b.invoke"
						}"""));

		Jwt callerJwt = Jwt.withTokenValue(CALLER_TOKEN_VALUE)
				.header("alg", "RS256")
				.subject("user-123")
				.issuedAt(Instant.now())
				.expiresAt(Instant.now().plusSeconds(300))
				.build();

		OAuth2AccessToken exchanged =
				tokenExchangeService.exchangeForServiceB(new JwtAuthenticationToken(callerJwt));

		assertThat(exchanged.getTokenValue()).isEqualTo("exchanged-token-for-service-b");

		RecordedRequest request = authServer.takeRequest();
		String body = request.getBody().readUtf8();
		// RFC 8693 grant and token-type URNs (URL-encoded in the form body).
		assertThat(body)
				.contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange")
				.contains("requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token")
				// The caller's JWT travels as the subject token, typed as a JWT.
				.contains("subject_token=" + CALLER_TOKEN_VALUE)
				.contains("subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt")
				// Downstream audience and scope we configured.
				.contains("audience=service-b")
				.contains("scope=service-b.invoke");
		// client_secret_basic puts credentials in the Authorization header, not the body.
		assertThat(request.getHeader("Authorization")).startsWith("Basic ");
	}
}
