package com.vizier.mcpsecurity.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Wires the RFC 8693 token-exchange client used by {@code TokenExchangeService}.
 *
 * <p>The provider is used directly (not through a request-bound
 * {@code OAuth2AuthorizedClientManager}) because this is a stateless resource server. The
 * one customization that matters: Spring does not send an {@code audience} parameter on a
 * token exchange by default, so we add one — a downstream resource server should validate
 * {@code aud}, and the exchanged token must therefore be minted for service B.
 */
@Configuration
public class TokenExchangeConfig {

	@Bean
	TokenExchangeOAuth2AuthorizedClientProvider tokenExchangeAuthorizedClientProvider(
			@Value("${mcp.token-exchange.audience}") String audience) {

		RestClientTokenExchangeTokenResponseClient responseClient =
				new RestClientTokenExchangeTokenResponseClient();
		// Add the downstream audience to the exchange request (not emitted by default).
		responseClient.addParametersConverter(grantRequest -> {
			MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
			parameters.add(OAuth2ParameterNames.AUDIENCE, audience);
			return parameters;
		});

		TokenExchangeOAuth2AuthorizedClientProvider provider =
				new TokenExchangeOAuth2AuthorizedClientProvider();
		provider.setAccessTokenResponseClient(responseClient);
		return provider;
	}
}
