package com.techStack.authSys.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;

@Slf4j
@Configuration
@EnableScheduling
public class SchedulingConfig {

    @Bean
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler scheduler = new ThreadPoolTaskScheduler();
        scheduler.setPoolSize(5); // Configure pool size as needed
        scheduler.setThreadNamePrefix("password-expiry-bot-");
        scheduler.setErrorHandler(t ->
                log.error("Error in scheduled task execution", t));
        scheduler.setWaitForTasksToCompleteOnShutdown(true);
        return scheduler;
    }
}
