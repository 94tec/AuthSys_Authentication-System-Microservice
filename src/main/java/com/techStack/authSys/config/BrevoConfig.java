package com.techStack.authSys.config;

import sendinblue.ApiClient;
import sibApi.TransactionalEmailsApi;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BrevoConfig {

    @Value("${brevo.api.key}")
    private String brevoApiKey;

    @Bean
    public ApiClient brevoApiClient() {
        ApiClient apiClient = new ApiClient();
        apiClient.setApiKey(brevoApiKey); // Set your API key
        return apiClient;
    }

    @Bean
    public TransactionalEmailsApi transactionalEmailsApi(ApiClient apiClient) {
        return new TransactionalEmailsApi(apiClient);
    }
}
