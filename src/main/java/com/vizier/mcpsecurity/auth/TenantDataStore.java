package com.vizier.mcpsecurity.auth;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A tenant-partitioned data store. Stands in for any real persistence layer; the point is
 * the access pattern, not the storage: every read and write is keyed first by tenant, so a
 * caller can only ever touch its own tenant's partition.
 *
 * <p>Because lookups are scoped by tenant, a record id that exists under another tenant is
 * simply "not found" for the current caller — isolation holds even against id guessing.
 */
public class TenantDataStore {

	// tenant id -> (record id -> value)
	private final Map<String, Map<String, String>> dataByTenant = new ConcurrentHashMap<>();

	/**
	 * Reads a record within a single tenant's partition.
	 *
	 * @return the value, or empty if this tenant has no such record (including when the id
	 *         belongs to a different tenant)
	 */
	public Optional<String> read(String tenant, String recordId) {
		return Optional.ofNullable(dataByTenant.getOrDefault(tenant, Map.of()).get(recordId));
	}

	/** Writes a record within a single tenant's partition. */
	public void write(String tenant, String recordId, String value) {
		dataByTenant.computeIfAbsent(tenant, t -> new ConcurrentHashMap<>()).put(recordId, value);
	}
}
