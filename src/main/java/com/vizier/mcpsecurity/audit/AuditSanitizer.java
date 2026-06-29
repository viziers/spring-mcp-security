package com.vizier.mcpsecurity.audit;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Redacts sensitive values from a tool's parameter map before they are written to the
 * audit log. A parameter is considered sensitive when its name contains any of the
 * configured fragments (case-insensitive), e.g. a {@code password} parameter.
 *
 * <p>This is a demonstration of the sanitization seam, not a guarantee against every form
 * of sensitive data — a secret passed in a blandly-named field would still be logged.
 */
public class AuditSanitizer {

	/** Placeholder written in place of a redacted value. */
	public static final String REDACTED = "***";

	private final Set<String> sensitiveFragments;

	/**
	 * @param sensitiveParameterNames parameter-name fragments whose values must be redacted
	 */
	public AuditSanitizer(Set<String> sensitiveParameterNames) {
		this.sensitiveFragments = sensitiveParameterNames.stream()
				.map(name -> name.toLowerCase(Locale.ROOT))
				.collect(Collectors.toUnmodifiableSet());
	}

	/**
	 * @return a copy of {@code parameters} with sensitive values replaced by {@link #REDACTED}
	 */
	public Map<String, Object> sanitize(Map<String, Object> parameters) {
		Map<String, Object> sanitized = new LinkedHashMap<>();
		parameters.forEach((name, value) ->
				sanitized.put(name, isSensitive(name) ? REDACTED : value));
		return sanitized;
	}

	private boolean isSensitive(String parameterName) {
		String lower = parameterName.toLowerCase(Locale.ROOT);
		return this.sensitiveFragments.stream().anyMatch(lower::contains);
	}
}
