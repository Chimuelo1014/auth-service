package com.sentinel.auth.client;

import com.sentinel.auth.client.dto.TenantCreationRequest;
import com.sentinel.auth.client.dto.TenantDTO;
import com.sentinel.auth.config.FeignClientConfig;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@FeignClient(
    name = "tenant-service",
    url = "${services.tenant.url}",
    configuration = FeignClientConfig.class
)
public interface TenantServiceClient {

    @PostMapping("/api/tenants/internal/create")
    TenantDTO createTenant(@RequestBody TenantCreationRequest request);
}