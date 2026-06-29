package com.vizier.mcpsecurity.tools;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.ActiveProfiles;

import com.vizier.mcpsecurity.auth.TenantContextHolder;
import com.vizier.mcpsecurity.support.WithMockJwt;

/**
 * Verifies multi-tenant isolation: a tool call only ever touches the caller's tenant
 * partition, so one tenant cannot read or write another tenant's data even when record ids
 * collide.
 */
@SpringBootTest
@ActiveProfiles("test")
class TenantIsolationTest {

	@Autowired
	private ExampleReadTool readTool;

	@Autowired
	private ExampleWriteTool writeTool;

	@AfterEach
	void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	@WithMockJwt(tenant = "tenant-a", scopes = "mcp:read")
	void tenantReadsItsOwnRecord() {
		assertThat(readTool.readExample("1")).isEqualTo("tenant-a record one");
	}

	@Test
	@WithMockJwt(tenant = "tenant-b", scopes = "mcp:read")
	void tenantSeesOnlyItsOwnPartitionForASharedId() {
		// Both tenants have a record "1"; tenant-b must see ITS record, not tenant-a's.
		assertThat(readTool.readExample("1")).isEqualTo("tenant-b record one");
	}

	@Test
	@WithMockJwt(tenant = "tenant-b", scopes = "mcp:read")
	void tenantCannotReadAnotherTenantsRecordById() {
		// Record "2" exists only under tenant-a; tenant-b gets "not found", no leakage.
		assertThat(readTool.readExample("2"))
				.doesNotContain("tenant-a")
				.contains("no record");
	}

	@Test
	void oneTenantsWriteIsInvisibleToAnother() {
		authenticate("tenant-b", "mcp:read", "mcp:write");
		writeTool.writeExample("shared-id", "tenant-b only");
		assertThat(readTool.readExample("shared-id")).isEqualTo("tenant-b only");

		authenticate("tenant-a", "mcp:read");
		assertThat(readTool.readExample("shared-id"))
				.doesNotContain("tenant-b only")
				.contains("no record");
	}

	private static void authenticate(String tenant, String... scopes) {
		Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
				.claim(TenantContextHolder.TENANT_CLAIM, tenant).build();
		List<GrantedAuthority> authorities = Arrays.stream(scopes)
				.map(scope -> (GrantedAuthority) new SimpleGrantedAuthority("SCOPE_" + scope))
				.toList();
		SecurityContextHolder.getContext()
				.setAuthentication(new JwtAuthenticationToken(jwt, authorities));
	}
}
