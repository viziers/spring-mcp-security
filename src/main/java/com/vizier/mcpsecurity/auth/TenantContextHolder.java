package com.vizier.mcpsecurity.auth;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Resolves the authenticated caller's tenant from the JWT {@code tenant_id} claim.
 *
 * <p>The tenant is read on demand from the current {@code SecurityContext} rather than
 * from a servlet-scoped {@code ThreadLocal}. MCP tool methods execute on a Reactor worker
 * thread (see the scope-enforcement design), where a request-thread {@code ThreadLocal}
 * would be empty; the {@code SecurityContext}, however, is propagated there. Reading the
 * claim off the current authentication therefore works both inside tool execution and on
 * a normal request thread.
 *
 * <p>Fails closed: a request with no authenticated JWT, or a JWT without a
 * {@code tenant_id}, has no tenant and cannot be scoped — this throws rather than
 * defaulting to some tenant.
 */
@Component
public class TenantContextHolder {

	/** JWT claim that carries the caller's tenant identifier. */
	public static final String TENANT_CLAIM = "tenant_id";

	/**
	 * @return the current caller's tenant id
	 * @throws IllegalStateException if there is no authenticated JWT or it has no tenant claim
	 */
	public String getCurrentTenant() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
			throw new IllegalStateException("No authenticated JWT; cannot resolve tenant");
		}
		String tenant = jwtAuthentication.getToken().getClaimAsString(TENANT_CLAIM);
		if (!StringUtils.hasText(tenant)) {
			throw new IllegalStateException("JWT has no '" + TENANT_CLAIM + "' claim; cannot resolve tenant");
		}
		return tenant;
	}
}
