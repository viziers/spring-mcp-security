package com.vizier.mcpsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.vizier.mcpsecurity.auth.TenantDataStore;

/**
 * Provides the in-memory tenant-scoped data store, seeded with demo records for two
 * tenants so multi-tenant isolation can be exercised. In a real system this bean would be
 * backed by a database (or any persistence layer); only this wiring would change.
 */
@Configuration
public class TenantConfig {

	@Bean
	TenantDataStore tenantDataStore() {
		TenantDataStore store = new TenantDataStore();
		// Same record ids across tenants on purpose: proves a caller cannot read another
		// tenant's record even by guessing an id that exists elsewhere.
		store.write("tenant-a", "1", "tenant-a record one");
		store.write("tenant-a", "2", "tenant-a record two");
		store.write("tenant-b", "1", "tenant-b record one");
		return store;
	}
}
