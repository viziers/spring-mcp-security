package com.vizier.mcpsecurity.wellknown;

import static org.hamcrest.Matchers.hasItem;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Verifies the OAuth 2.0 Authorization Server Metadata document (RFC 8414) is publicly
 * reachable (no token) and carries the expected discovery fields.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthorizationServerMetadataControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void metadataIsPublicAndContainsRfc8414Fields() throws Exception {
		mockMvc.perform(get("/.well-known/oauth-authorization-server"))
				.andExpect(status().isOk())
				.andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.issuer").value("https://auth.example.com"))
				.andExpect(jsonPath("$.token_endpoint").exists())
				.andExpect(jsonPath("$.authorization_endpoint").exists())
				.andExpect(jsonPath("$.jwks_uri").exists())
				.andExpect(jsonPath("$.scopes_supported").isArray())
				.andExpect(jsonPath("$.scopes_supported[0]").value("mcp:read"))
				.andExpect(jsonPath("$.grant_types_supported")
						.value(hasItem("urn:ietf:params:oauth:grant-type:token-exchange")));
	}
}
