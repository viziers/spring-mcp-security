package com.vizier.mcpsecurity.config;

import org.springframework.ai.tool.ToolCallbackProvider;
import org.springframework.ai.tool.method.MethodToolCallbackProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.vizier.mcpsecurity.tools.ExampleReadTool;
import com.vizier.mcpsecurity.tools.ExampleWriteTool;

/**
 * Registers the MCP tools with the Spring AI MCP server.
 *
 * <p>The MCP server auto-configuration discovers {@link ToolCallbackProvider} beans and
 * exposes the methods annotated with {@code @Tool} on the supplied objects as MCP tools.
 * The tool objects are injected as Spring beans so that the {@code @PreAuthorize} scope
 * guards on their methods are honored (method security applies to the proxied beans).
 */
@Configuration
public class McpServerConfig {

	@Bean
	ToolCallbackProvider mcpTools(ExampleReadTool exampleReadTool, ExampleWriteTool exampleWriteTool) {
		return MethodToolCallbackProvider.builder()
				.toolObjects(exampleReadTool, exampleWriteTool)
				.build();
	}
}
