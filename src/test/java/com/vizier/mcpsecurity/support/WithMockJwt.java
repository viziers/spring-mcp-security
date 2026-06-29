package com.vizier.mcpsecurity.support;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.security.test.context.support.WithSecurityContext;

/**
 * Test annotation that populates the {@code SecurityContext} with a
 * {@code JwtAuthenticationToken} carrying a {@code tenant_id} claim and {@code SCOPE_}
 * authorities — what the secured, tenant-scoped tools actually read at runtime.
 *
 * <p>Use in place of {@code @WithMockUser}, whose principal is not a {@code Jwt} and so
 * carries no tenant claim.
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
@WithSecurityContext(factory = WithMockJwtSecurityContextFactory.class)
public @interface WithMockJwt {

	/** JWT subject. */
	String subject() default "user";

	/** Tenant id placed in the {@code tenant_id} claim. Blank means no tenant claim. */
	String tenant() default "tenant-a";

	/** OAuth scopes; each becomes a {@code SCOPE_<scope>} authority. */
	String[] scopes() default {};
}
