package com.vizier.mcpsecurity.config;

import java.util.List;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Validates that a JWT carries this resource server in its {@code aud} (audience) claim
 * (RFC 7519 §4.1.3).
 *
 * <p>A valid signature only proves that a key we trust signed the token. It does not
 * prove the token was minted <em>for this server</em>. Without an audience check, a token
 * issued for another service that shares the same authorization server would be accepted
 * here — a token-redirection weakness. This validator closes that gap and is registered
 * alongside the timestamp and issuer validators in {@link SecurityConfig#jwtDecoder()}.
 */
public final class AudienceValidator implements OAuth2TokenValidator<Jwt> {

	private final String requiredAudience;
	private final OAuth2Error error;

	/**
	 * @param requiredAudience the audience value this resource server must appear as in a
	 *                         token's {@code aud} claim
	 */
	public AudienceValidator(String requiredAudience) {
		this.requiredAudience = requiredAudience;
		// "invalid_token" is the RFC 6750 error code a resource server returns for a token
		// that fails validation; it surfaces to the client as a 401 with this description.
		this.error = new OAuth2Error("invalid_token",
				"The required audience '" + requiredAudience + "' is missing", null);
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		List<String> audiences = jwt.getAudience();
		if (audiences != null && audiences.contains(requiredAudience)) {
			return OAuth2TokenValidatorResult.success();
		}
		return OAuth2TokenValidatorResult.failure(error);
	}
}
