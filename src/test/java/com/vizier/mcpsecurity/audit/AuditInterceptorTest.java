package com.vizier.mcpsecurity.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

/**
 * Unit tests for {@link AuditInterceptor}: each invocation emits one JSON audit line with
 * the identity, tenant, tool, sanitized parameters, and outcome; failures are recorded and
 * rethrown. Uses a mock join point and a captured log appender — no Spring context needed.
 */
class AuditInterceptorTest {

	private final ObjectMapper objectMapper = new ObjectMapper();
	private final AuditInterceptor interceptor =
			new AuditInterceptor(objectMapper, Set.of("password"));
	private final Logger auditLogger = (Logger) LoggerFactory.getLogger(AuditInterceptor.class);
	private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

	@BeforeEach
	void setUp() {
		appender.start();
		auditLogger.addAppender(appender);
		Jwt jwt = Jwt.withTokenValue("t").header("alg", "none")
				.subject("user-1").claim("tenant_id", "tenant-a").build();
		SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
	}

	@AfterEach
	void tearDown() {
		auditLogger.detachAppender(appender);
		SecurityContextHolder.clearContext();
	}

	private static ProceedingJoinPoint joinPoint(String method, String[] names, Object[] args) {
		MethodSignature signature = mock(MethodSignature.class);
		when(signature.getName()).thenReturn(method);
		when(signature.getParameterNames()).thenReturn(names);
		ProceedingJoinPoint joinPoint = mock(ProceedingJoinPoint.class);
		when(joinPoint.getSignature()).thenReturn(signature);
		when(joinPoint.getArgs()).thenReturn(args);
		return joinPoint;
	}

	private JsonNode onlyAuditLine() throws Exception {
		assertThat(appender.list).hasSize(1);
		return objectMapper.readTree(appender.list.get(0).getFormattedMessage());
	}

	@Test
	void logsSuccessWithIdentityTenantToolAndParameters() throws Throwable {
		ProceedingJoinPoint joinPoint = joinPoint("readExample", new String[] { "id" }, new Object[] { "1" });
		when(joinPoint.proceed()).thenReturn("result");

		Object result = interceptor.audit(joinPoint);

		assertThat(result).isEqualTo("result");
		JsonNode event = onlyAuditLine();
		assertThat(event.get("principal").asText()).isEqualTo("user-1");
		assertThat(event.get("tenant").asText()).isEqualTo("tenant-a");
		assertThat(event.get("tool").asText()).isEqualTo("readExample");
		assertThat(event.get("outcome").asText()).isEqualTo("SUCCESS");
		assertThat(event.get("parameters").get("id").asText()).isEqualTo("1");
		assertThat(event.get("timestamp").asText()).isNotBlank();
	}

	@Test
	void redactsSensitiveParameterValues() throws Throwable {
		ProceedingJoinPoint joinPoint = joinPoint("login", new String[] { "password" }, new Object[] { "hunter2" });
		when(joinPoint.proceed()).thenReturn("ok");

		interceptor.audit(joinPoint);

		assertThat(onlyAuditLine().get("parameters").get("password").asText())
				.isEqualTo(AuditSanitizer.REDACTED);
	}

	@Test
	void recordsFailureAndRethrows() throws Throwable {
		ProceedingJoinPoint joinPoint = joinPoint("readExample", new String[] { "id" }, new Object[] { "1" });
		when(joinPoint.proceed()).thenThrow(new IllegalStateException("boom"));

		assertThatThrownBy(() -> interceptor.audit(joinPoint))
				.isInstanceOf(IllegalStateException.class);

		JsonNode event = onlyAuditLine();
		assertThat(event.get("outcome").asText()).isEqualTo("FAILURE");
		assertThat(event.get("error").asText()).contains("IllegalStateException");
	}
}
