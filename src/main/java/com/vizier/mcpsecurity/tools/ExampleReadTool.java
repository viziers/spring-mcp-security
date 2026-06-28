package com.vizier.mcpsecurity.tools;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/**
 * Example read-only MCP tool, gated on the {@code mcp:read} OAuth scope.
 *
 * <p>The required scope is declared in the {@link PreAuthorize} annotation, so the tool
 * self-documents its permission. Spring Security maps the JWT {@code scope}/{@code scp}
 * claim to {@code SCOPE_}-prefixed authorities, so {@code mcp:read} becomes the authority
 * {@code SCOPE_mcp:read}. Enforcement happens at the method level: an unauthorized call
 * never reaches the tool body.
 *
 * <p>This guard is reliable only because the {@code mcp-security} module propagates the
 * authenticated {@code SecurityContext} into MCP tool execution (which otherwise runs on a
 * Reactor worker thread without it).
 */
@Service
public class ExampleReadTool {

	@PreAuthorize("hasAuthority('SCOPE_mcp:read')")
	@Tool(description = "Reads an example record by id for the authenticated caller")
	public String readExample(@ToolParam(description = "Record identifier") String id) {
		return "example record " + id;
	}
}
