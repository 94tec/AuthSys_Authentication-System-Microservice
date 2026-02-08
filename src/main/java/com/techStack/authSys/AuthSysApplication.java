package com.techStack.authSys;


import com.techStack.authSys.config.core.AppConfigProperties;
import com.techStack.authSys.config.security.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import com.google.cloud.spring.data.firestore.repository.config.EnableReactiveFirestoreRepositories;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;

import java.time.Clock;

@SpringBootApplication
@ConfigurationPropertiesScan("com.techStack.authSys.config")
@EnableConfigurationProperties({AppConfigProperties.class, JwtConfig.class})
@EnableReactiveFirestoreRepositories
@EnableAsync
@EnableCaching
public class AuthSysApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthSysApplication.class, args);
		System.out.println("AuthSys Application started successfully!");
	}

}
