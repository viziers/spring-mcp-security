package com.vizier.mcpsecurity.tools;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.test.context.ActiveProfiles;

import com.vizier.mcpsecurity.support.WithMockJwt;

/**
 * Verifies per-tool scope enforcement: each tool's {@code @PreAuthorize} guard admits a
 * caller holding the matching {@code SCOPE_} authority and rejects everyone else.
 *
 * <p>The tools are invoked as Spring beans so method security applies. This exercises the
 * authorization decision directly; propagating the {@code SecurityContext} into the MCP
 * runtime's worker thread is the {@code mcp-security} module's responsibility (covered by
 * that module's own integration tests) and is not re-tested here.
 */
@SpringBootTest
@ActiveProfiles("test")
class ToolScopeEnforcementTest {

	@Autowired
	private ExampleReadTool readTool;

	@Autowired
	private ExampleWriteTool writeTool;

	@Test
	@WithMockJwt(scopes = "mcp:read")
	void readToolAllowedWithReadScope() {
		assertThat(readTool.readExample("1")).isEqualTo("tenant-a record one");
	}

	@Test
	@WithMockJwt(scopes = "mcp:write")
	void readToolDeniedWithoutReadScope() {
		assertThatThrownBy(() -> readTool.readExample("1"))
				.isInstanceOf(AccessDeniedException.class);
	}

	@Test
	@WithMockJwt(scopes = "mcp:write")
	void writeToolAllowedWithWriteScope() {
		assertThat(writeTool.writeExample("9", "value")).contains("value");
	}

	@Test
	@WithMockJwt(scopes = "mcp:read")
	void writeToolDeniedWithoutWriteScope() {
		assertThatThrownBy(() -> writeTool.writeExample("9", "value"))
				.isInstanceOf(AccessDeniedException.class);
	}

	@Test
	void toolDeniedWhenUnauthenticated() {
		assertThatThrownBy(() -> readTool.readExample("1"))
				.isInstanceOf(AuthenticationCredentialsNotFoundException.class);
	}
}
