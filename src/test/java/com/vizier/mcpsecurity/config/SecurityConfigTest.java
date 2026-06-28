package com.vizier.mcpsecurity.config;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;

/**
 * Verifies the resource-server boundary defined by {@link SecurityConfig}:
 * <ul>
 *   <li>a protected endpoint returns 401 without a token,</li>
 *   <li>the same endpoint is reachable with a valid JWT, and</li>
 *   <li>a public endpoint is reachable without any token.</li>
 * </ul>
 *
 * <p>The {@code jwt()} post-processor injects an authenticated principal directly, so the
 * test exercises the authorization rules without needing a live authorization server.
 * A pair of throwaway endpoints is registered only for this test (see {@link TestWebConfig});
 * the real protected resources are the MCP tools added in a later section.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigTest {

	@Autowired
	private MockMvc mockMvc;

	@Test
	void protectedEndpointWithoutTokenReturns401() throws Exception {
		mockMvc.perform(get("/api/secure-ping"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	void protectedEndpointWithJwtReturns200() throws Exception {
		mockMvc.perform(get("/api/secure-ping").with(jwt()))
				.andExpect(status().isOk());
	}

	@Test
	void publicEndpointWithoutTokenReturns200() throws Exception {
		mockMvc.perform(get("/"))
				.andExpect(status().isOk());
	}

	/**
	 * Registers two endpoints used only by this test: a public root and a protected path.
	 * Nested {@code @TestConfiguration} classes are picked up automatically by the
	 * surrounding {@code @SpringBootTest}.
	 */
	@TestConfiguration
	static class TestWebConfig {

		@Bean
		TestPingController testPingController() {
			return new TestPingController();
		}
	}

	@RestController
	static class TestPingController {

		@GetMapping("/")
		String publicPing() {
			return "public";
		}

		@GetMapping("/api/secure-ping")
		String securePing() {
			return "secure";
		}
	}
}
