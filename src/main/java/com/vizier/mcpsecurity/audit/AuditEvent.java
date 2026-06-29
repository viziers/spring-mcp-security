package com.vizier.mcpsecurity.audit;

import java.util.Map;

/**
 * One audit record for an MCP tool invocation, serialized to a single JSON log line.
 *
 * @param timestamp  ISO-8601 instant the invocation was recorded
 * @param principal  authenticated identity (the JWT {@code sub}), or {@code null} if none
 * @param tenant     the caller's tenant ({@code tenant_id} claim), or {@code null} if none
 * @param tool       the tool (method) name
 * @param parameters sanitized input parameters (name to value, sensitive values redacted)
 * @param outcome    {@code SUCCESS} or {@code FAILURE}
 * @param error      the exception class name when {@code outcome} is FAILURE, else {@code null}
 */
public record AuditEvent(
		String timestamp,
		String principal,
		String tenant,
		String tool,
		Map<String, Object> parameters,
		String outcome,
		String error) {

	public static final String SUCCESS = "SUCCESS";
	public static final String FAILURE = "FAILURE";
}
