package com.vizier.mcpsecurity.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.context.ActiveProfiles;

import com.vizier.mcpsecurity.support.WithMockJwt;
import com.vizier.mcpsecurity.tools.ExampleReadTool;

/**
 * Verifies the audit aspect is actually wired to {@code @Tool} methods: invoking a real
 * tool through the Spring proxy emits a JSON audit line carrying the tenant, tool, and
 * outcome. This guards the pointcut (a wrong pointcut would silently audit nothing).
 */
@SpringBootTest
@ActiveProfiles("test")
@ExtendWith(OutputCaptureExtension.class)
class AuditLoggingIntegrationTest {

	@Autowired
	private ExampleReadTool readTool;

	@Test
	@WithMockJwt(tenant = "tenant-a", scopes = "mcp:read")
	void toolInvocationEmitsAuditLine(CapturedOutput output) {
		readTool.readExample("1");

		assertThat(output)
				.contains("\"tool\":\"readExample\"")
				.contains("\"tenant\":\"tenant-a\"")
				.contains("\"outcome\":\"SUCCESS\"");
	}
}
