package com.vizier.mcpsecurity.auth;

import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

/**
 * Performs RFC 8693 OAuth 2.0 Token Exchange: trades the caller's validated JWT for a new
 * access token scoped to a downstream service ("service B"), preserving the caller's
 * identity so it travels across the service boundary without credential re-entry.
 *
 * <p>The caller's {@link JwtAuthenticationToken} is supplied to the
 * {@link TokenExchangeOAuth2AuthorizedClientProvider} as the authorization principal. The
 * provider's default subject-token resolver reads {@code principal.getPrincipal()} — for a
 * {@code JwtAuthenticationToken} that is the {@code Jwt} (an {@code OAuth2Token}) — and
 * sends it as the {@code subject_token}. The authorization server then mints a token whose
 * {@code sub} continues to identify the original user (delegation), scoped to service B.
 */
@Service
public class TokenExchangeService {

	/** Matches the {@code spring.security.oauth2.client.registration.<id>} in application.yml. */
	static final String SERVICE_B_REGISTRATION_ID = "service-b";

	private final ClientRegistrationRepository clientRegistrations;
	private final TokenExchangeOAuth2AuthorizedClientProvider tokenExchangeProvider;

	public TokenExchangeService(ClientRegistrationRepository clientRegistrations,
			TokenExchangeOAuth2AuthorizedClientProvider tokenExchangeProvider) {
		this.clientRegistrations = clientRegistrations;
		this.tokenExchangeProvider = tokenExchangeProvider;
	}

	/**
	 * Exchanges the caller's JWT for a token valid at service B.
	 *
	 * @param authentication the current authenticated caller (its {@code Jwt} is the subject token)
	 * @return the exchanged access token, scoped to service B
	 */
	public OAuth2AccessToken exchangeForServiceB(JwtAuthenticationToken authentication) {
		ClientRegistration registration =
				this.clientRegistrations.findByRegistrationId(SERVICE_B_REGISTRATION_ID);
		if (registration == null) {
			throw new IllegalStateException(
					"No client registration found for '" + SERVICE_B_REGISTRATION_ID + "'");
		}

		OAuth2AuthorizationContext context = OAuth2AuthorizationContext
				.withClientRegistration(registration)
				.principal(authentication)
				.build();

		OAuth2AuthorizedClient authorizedClient = this.tokenExchangeProvider.authorize(context);
		if (authorizedClient == null) {
			// The provider returns null (rather than throwing) when it cannot perform the
			// exchange — e.g. the principal does not carry an OAuth2Token subject token.
			throw new IllegalStateException("Token exchange did not produce an access token");
		}
		return authorizedClient.getAccessToken();
	}
}
