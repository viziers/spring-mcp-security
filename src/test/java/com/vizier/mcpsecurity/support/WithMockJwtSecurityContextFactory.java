package com.vizier.mcpsecurity.support;

import java.util.Arrays;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.test.context.support.WithSecurityContextFactory;
import org.springframework.util.StringUtils;

import com.vizier.mcpsecurity.auth.TenantContextHolder;

/**
 * Builds the {@code SecurityContext} for {@link WithMockJwt}: a {@code JwtAuthenticationToken}
 * whose {@code Jwt} carries the requested {@code tenant_id} claim and whose authorities are
 * the requested scopes, each prefixed with {@code SCOPE_} (matching Spring Security's
 * default scope-to-authority mapping).
 */
public class WithMockJwtSecurityContextFactory implements WithSecurityContextFactory<WithMockJwt> {

	@Override
	public SecurityContext createSecurityContext(WithMockJwt annotation) {
		Jwt.Builder builder = Jwt.withTokenValue("test-token")
				.header("alg", "none")
				.subject(annotation.subject());
		if (StringUtils.hasText(annotation.tenant())) {
			builder.claim(TenantContextHolder.TENANT_CLAIM, annotation.tenant());
		}
		Jwt jwt = builder.build();

		List<GrantedAuthority> authorities = Arrays.stream(annotation.scopes())
				.map(scope -> (GrantedAuthority) new SimpleGrantedAuthority("SCOPE_" + scope))
				.toList();

		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(new JwtAuthenticationToken(jwt, authorities));
		return context;
	}
}
