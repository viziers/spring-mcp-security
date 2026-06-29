package com.vizier.mcpsecurity.config;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.ActiveProfiles;

/**
 * Verifies error responses are not masked as 401 by the servlet ERROR dispatch.
 *
 * <p>A permit-listed path with no handler (e.g. {@code /}) returns 404, which forwards to
 * {@code /error} as an ERROR dispatch; without permitting that dispatch it would come back
 * as 401. A genuinely protected path is still rejected (401) on its REQUEST dispatch.
 *
 * <p>Uses a real servlet container ({@code RANDOM_PORT}) on purpose: MockMvc does not
 * perform the error dispatch, so it cannot reproduce this behavior. The {@code test}
 * profile excludes the MCP chain (which needs a live authorization server).
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
class ErrorDispatchAuthorizationTest {

	@Autowired
	private TestRestTemplate restTemplate;

	@Test
	void permittedPathWithNoHandlerReturns404NotMaskedAs401() {
		// "/" is permitAll but has no controller, so it 404s and forwards to /error.
		assertThat(restTemplate.getForEntity("/", String.class).getStatusCode())
				.isEqualTo(HttpStatus.NOT_FOUND);
	}

	@Test
	void protectedPathStillRequiresAuthentication() {
		// Not in the permit-list: rejected on the REQUEST dispatch before any handler.
		assertThat(restTemplate.getForEntity("/needs-authentication", String.class).getStatusCode())
				.isEqualTo(HttpStatus.UNAUTHORIZED);
	}
}
