package com.vizier.mcpsecurity.tools;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * Example write MCP tool, gated on the {@code mcp:write} OAuth scope.
 *
 * <p>Demonstrates least-privilege at the tool granularity: a caller holding only
 * {@code mcp:read} can invoke {@link ExampleReadTool} but is denied here. The required
 * scope is declared on the method, so the tool self-documents its permission, and
 * enforcement happens before the tool body runs.
 */
@Service
public class ExampleWriteTool {

	@PreAuthorize("hasAuthority('SCOPE_mcp:write')")
	@Tool(description = "Writes an example record value for the authenticated caller")
	public String writeExample(
			@ToolParam(description = "Record identifier") String id,
			@ToolParam(description = "Value to store") String value) {
		return "stored '" + value + "' at example record " + id;
	}
}
