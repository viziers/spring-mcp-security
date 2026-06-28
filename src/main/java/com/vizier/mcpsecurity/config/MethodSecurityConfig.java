package com.vizier.mcpsecurity.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

/**
 * Enables Spring Security method security so the {@code @PreAuthorize} scope guards on the
 * MCP tool methods are enforced.
 *
 * <p>Kept separate from {@link McpSecurityConfig} so method security is always active —
 * including in hermetic tests that exercise the tool guards directly but do not load the
 * MCP web chain (which requires a reachable authorization server for OIDC discovery).
 */
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
}
