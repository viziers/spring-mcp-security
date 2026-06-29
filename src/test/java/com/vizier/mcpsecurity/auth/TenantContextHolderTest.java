package com.vizier.mcpsecurity.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * Unit tests for {@link TenantContextHolder}: it returns the {@code tenant_id} claim of the
 * current JWT, and fails closed when there is no tenant to resolve.
 */
class TenantContextHolderTest {

	private final TenantContextHolder tenantContextHolder = new TenantContextHolder();

	@AfterEach
	void clearContext() {
		SecurityContextHolder.clearContext();
	}

	private static void authenticateWith(Jwt jwt) {
		SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
	}

	@Test
	void returnsTenantFromClaim() {
		authenticateWith(Jwt.withTokenValue("t").header("alg", "none")
				.claim(TenantContextHolder.TENANT_CLAIM, "tenant-a").build());

		assertThat(tenantContextHolder.getCurrentTenant()).isEqualTo("tenant-a");
	}

	@Test
	void throwsWhenNoAuthentication() {
		assertThatThrownBy(tenantContextHolder::getCurrentTenant)
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void throwsWhenJwtHasNoTenantClaim() {
		authenticateWith(Jwt.withTokenValue("t").header("alg", "none").subject("user").build());

		assertThatThrownBy(tenantContextHolder::getCurrentTenant)
				.isInstanceOf(IllegalStateException.class);
	}

	@Test
	void throwsWhenAuthenticationIsNotJwt() {
		SecurityContextHolder.getContext()
				.setAuthentication(new UsernamePasswordAuthenticationToken("user", "password"));

		assertThatThrownBy(tenantContextHolder::getCurrentTenant)
				.isInstanceOf(IllegalStateException.class);
	}
}
