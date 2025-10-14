package com.techStack.authSys.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;
import java.util.Properties;

@Configuration
public class EmailConfig {

    @Value("${spring.mail.host}") private String host;
    @Value("${spring.mail.port}") private int port;
    @Value("${spring.mail.username}") private String username;
    @Value("${spring.mail.password}") private String password;
    @Value("${spring.mail.protocol}") private String protocol;
    @Value("${spring.mail.properties.mail.smtp.auth}") private String smtpAuth;
    @Value("${spring.mail.properties.mail.smtp.starttls.enable}") private String starttls;
    @Value("${spring.mail.properties.mail.smtp.connectiontimeout}") private int connectionTimeout;
    @Value("${spring.mail.properties.mail.smtp.timeout}") private int timeout;
    @Value("${spring.mail.properties.mail.smtp.writetimeout}") private int writeTimeout;

    @Bean
    public JavaMailSender javaMailSender() {
        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(host);
        mailSender.setPort(port);
        mailSender.setUsername(username);
        mailSender.setPassword(password);
        mailSender.setProtocol(protocol);

        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.smtp.auth", smtpAuth);
        props.put("mail.smtp.starttls.enable", starttls);
        props.put("mail.smtp.connectiontimeout", connectionTimeout);
        props.put("mail.smtp.timeout", timeout);
        props.put("mail.smtp.writetimeout", writeTimeout);

        return mailSender;
    }

    @Bean
    public Scheduler emailScheduler() {
        return Schedulers.boundedElastic();
    }
}
