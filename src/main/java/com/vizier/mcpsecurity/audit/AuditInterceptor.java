package com.vizier.mcpsecurity.audit;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vizier.mcpsecurity.auth.TenantContextHolder;

/**
 * Audits every MCP tool invocation. Implemented as a Spring AOP {@code @Around} aspect over
 * methods annotated {@code @Tool}, so the tool code carries no audit logic and any new tool
 * is audited automatically.
 *
 * <p>The aspect runs at the default (lowest) precedence, i.e. <em>inside</em> Spring
 * Security's method interceptor, so only authorized invocations are audited and the
 * authenticated identity is always present. It records the principal ({@code sub}), tenant
 * ({@code tenant_id}), tool name, sanitized parameters, outcome, and timestamp as a single
 * JSON line suitable for ingestion into a log aggregator.
 */
@Aspect
@Component
public class AuditInterceptor {

	private static final Logger log = LoggerFactory.getLogger(AuditInterceptor.class);

	private final ObjectMapper objectMapper;
	private final AuditSanitizer sanitizer;

	public AuditInterceptor(ObjectMapper objectMapper,
			@Value("${mcp.audit.sensitive-parameters}") Set<String> sensitiveParameters) {
		this.objectMapper = objectMapper;
		this.sanitizer = new AuditSanitizer(sensitiveParameters);
	}

	@Around("@annotation(org.springframework.ai.tool.annotation.Tool)")
	public Object audit(ProceedingJoinPoint joinPoint) throws Throwable {
		String tool = joinPoint.getSignature().getName();
		Map<String, Object> parameters = this.sanitizer.sanitize(parametersOf(joinPoint));
		String principal = currentPrincipal();
		String tenant = currentTenant();
		try {
			Object result = joinPoint.proceed();
			record(principal, tenant, tool, parameters, AuditEvent.SUCCESS, null);
			return result;
		}
		catch (Throwable ex) {
			record(principal, tenant, tool, parameters, AuditEvent.FAILURE, ex.getClass().getName());
			throw ex;
		}
	}

	/** Builds an ordered name→value map of the call's arguments. */
	private Map<String, Object> parametersOf(ProceedingJoinPoint joinPoint) {
		MethodSignature signature = (MethodSignature) joinPoint.getSignature();
		String[] names = signature.getParameterNames();
		Object[] args = joinPoint.getArgs();
		Map<String, Object> parameters = new LinkedHashMap<>();
		for (int i = 0; i < args.length; i++) {
			String name = (names != null && i < names.length && names[i] != null) ? names[i] : "arg" + i;
			parameters.put(name, args[i]);
		}
		return parameters;
	}

	private String currentPrincipal() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		return (authentication != null) ? authentication.getName() : null;
	}

	private String currentTenant() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
			return jwtAuthentication.getToken().getClaimAsString(TenantContextHolder.TENANT_CLAIM);
		}
		return null;
	}

	private void record(String principal, String tenant, String tool,
			Map<String, Object> parameters, String outcome, String error) {
		AuditEvent event = new AuditEvent(Instant.now().toString(), principal, tenant, tool,
				parameters, outcome, error);
		try {
			log.info(this.objectMapper.writeValueAsString(event));
		}
		catch (JsonProcessingException ex) {
			// Never let auditing break the tool call; record the failure to serialize instead.
			log.warn("Failed to serialize audit event for tool '{}'", tool, ex);
		}
	}
}
