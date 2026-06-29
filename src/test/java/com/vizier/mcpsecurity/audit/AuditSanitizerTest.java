package com.vizier.mcpsecurity.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link AuditSanitizer}: values are redacted when the parameter name
 * matches a sensitive fragment (case-insensitive), and passed through otherwise.
 */
class AuditSanitizerTest {

	private final AuditSanitizer sanitizer = new AuditSanitizer(Set.of("password", "secret"));

	@Test
	void redactsValuesForSensitivelyNamedParameters() {
		Map<String, Object> parameters = new LinkedHashMap<>();
		parameters.put("id", "1");
		parameters.put("password", "hunter2");
		parameters.put("apiSecret", "abc123"); // contains "secret"

		Map<String, Object> sanitized = sanitizer.sanitize(parameters);

		assertThat(sanitized.get("id")).isEqualTo("1");
		assertThat(sanitized.get("password")).isEqualTo(AuditSanitizer.REDACTED);
		assertThat(sanitized.get("apiSecret")).isEqualTo(AuditSanitizer.REDACTED);
	}

	@Test
	void passesThroughWhenNothingIsSensitive() {
		Map<String, Object> sanitized = sanitizer.sanitize(Map.of("id", "1", "value", "v"));

		assertThat(sanitized).containsEntry("id", "1").containsEntry("value", "v");
	}
}
