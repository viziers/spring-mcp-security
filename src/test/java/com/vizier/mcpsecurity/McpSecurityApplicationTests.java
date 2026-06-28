package com.vizier.mcpsecurity;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

// The MCP security chain performs OIDC discovery against a live issuer at startup, so the
// hermetic test suite runs under the "test" profile, which excludes that chain.
@SpringBootTest
@ActiveProfiles("test")
class McpSecurityApplicationTests {

	@Test
	void contextLoads() {
	}

}
