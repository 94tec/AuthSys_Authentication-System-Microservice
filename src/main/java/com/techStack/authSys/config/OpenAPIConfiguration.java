package com.techStack.authSys.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenAPIConfiguration {
    @Bean
    public OpenAPI defineOpenApi() {
        Server server = new Server();
        server.setUrl("http://localhost:8000");
        server.setDescription("Development");

        Contact contact = new Contact();
        contact.setName("Fixtone Kaloki");
        contact.setEmail("m.damuchi.ke@email.com");

        Info info = new Info()
                .title("Auth Microservice API")
                .version("1.0")
                .description("API Description")
                .contact(contact);

        return new OpenAPI()
                .info(info)
                .servers(List.of(server));
    }
}
