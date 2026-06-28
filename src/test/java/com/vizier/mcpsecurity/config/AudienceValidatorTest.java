package com.vizier.mcpsecurity.config;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Unit tests for {@link AudienceValidator}: a token is accepted only when the required
 * audience appears in its {@code aud} claim.
 */
class AudienceValidatorTest {

	private static final String REQUIRED_AUDIENCE = "mcp-server";

	private final AudienceValidator validator = new AudienceValidator(REQUIRED_AUDIENCE);

	private static Jwt jwtWithAudience(List<String> audience) {
		return Jwt.withTokenValue("token")
				.header("alg", "RS256")
				.subject("user")
				.audience(audience)
				.build();
	}

	@Test
	void succeedsWhenRequiredAudiencePresent() {
		Jwt jwt = jwtWithAudience(List.of(REQUIRED_AUDIENCE, "another-service"));

		assertThat(validator.validate(jwt).hasErrors()).isFalse();
	}

	@Test
	void failsWhenRequiredAudienceMissing() {
		Jwt jwt = jwtWithAudience(List.of("another-service"));

		assertThat(validator.validate(jwt).hasErrors()).isTrue();
	}

	@Test
	void failsWhenNoAudienceClaim() {
		Jwt jwt = Jwt.withTokenValue("token").header("alg", "RS256").subject("user").build();

		assertThat(validator.validate(jwt).hasErrors()).isTrue();
	}
}
