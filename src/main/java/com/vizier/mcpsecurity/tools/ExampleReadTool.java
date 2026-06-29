package com.vizier.mcpsecurity.tools;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.vizier.mcpsecurity.auth.TenantContextHolder;
import com.vizier.mcpsecurity.auth.TenantDataStore;

/**
 * Example read-only MCP tool, gated on the {@code mcp:read} OAuth scope and scoped to the
 * caller's tenant.
 *
 * <p>Two layers of access control apply: the {@link PreAuthorize} guard requires the
 * {@code mcp:read} scope (mapped from the JWT to {@code SCOPE_mcp:read}), and the read is
 * partitioned by the caller's tenant (from the JWT {@code tenant_id} claim) so it can only
 * ever return that tenant's data. A record id belonging to another tenant is "not found".
 *
 * <p>Both the scope guard and tenant resolution rely on the authenticated
 * {@code SecurityContext} being propagated into MCP tool execution (which runs on a
 * Reactor worker thread).
 */
@Service
public class ExampleReadTool {

	private final TenantContextHolder tenantContextHolder;
	private final TenantDataStore tenantDataStore;

	public ExampleReadTool(TenantContextHolder tenantContextHolder, TenantDataStore tenantDataStore) {
		this.tenantContextHolder = tenantContextHolder;
		this.tenantDataStore = tenantDataStore;
	}

	@PreAuthorize("hasAuthority('SCOPE_mcp:read')")
	@Tool(description = "Reads an example record by id within the authenticated caller's tenant")
	public String readExample(@ToolParam(description = "Record identifier") String id) {
		String tenant = this.tenantContextHolder.getCurrentTenant();
		return this.tenantDataStore.read(tenant, id)
				.orElse("no record '" + id + "' for tenant '" + tenant + "'");
	}
}
