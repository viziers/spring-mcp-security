package com.vizier.mcpsecurity.tools;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.vizier.mcpsecurity.auth.TenantContextHolder;
import com.vizier.mcpsecurity.auth.TenantDataStore;

/**
 * Example write MCP tool, gated on the {@code mcp:write} OAuth scope and scoped to the
 * caller's tenant.
 *
 * <p>Demonstrates least-privilege at the tool granularity (a {@code mcp:read}-only caller
 * is denied) and tenant isolation on writes: the record is stored in the caller's tenant
 * partition (from the JWT {@code tenant_id} claim) and cannot land in another tenant's data.
 */
@Service
public class ExampleWriteTool {

	private final TenantContextHolder tenantContextHolder;
	private final TenantDataStore tenantDataStore;

	public ExampleWriteTool(TenantContextHolder tenantContextHolder, TenantDataStore tenantDataStore) {
		this.tenantContextHolder = tenantContextHolder;
		this.tenantDataStore = tenantDataStore;
	}

	@PreAuthorize("hasAuthority('SCOPE_mcp:write')")
	@Tool(description = "Writes an example record value within the authenticated caller's tenant")
	public String writeExample(
			@ToolParam(description = "Record identifier") String id,
			@ToolParam(description = "Value to store") String value) {
		String tenant = this.tenantContextHolder.getCurrentTenant();
		this.tenantDataStore.write(tenant, id, value);
		return "stored '" + value + "' at record '" + id + "' for tenant '" + tenant + "'";
	}
}
