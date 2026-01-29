package com.techStack.authSys.config.intergration;

import com.techStack.authSys.util.validation.HelperUtils;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
    private static final Logger log = LoggerFactory.getLogger(EmailConfig.class);

    @Value("${spring.mail.host}") private String host;
    @Value("${spring.mail.port}") private int port;
    @Value("${spring.mail.username}") private String username;
    @Value("${spring.mail.password}") private String password;
    @Value("${spring.mail.protocol}") private String protocol;
    @Value("${spring.mail.from:${spring.mail.username}}") private String fromAddress;
    @Value("${spring.mail.properties.mail.smtp.auth}") private String smtpAuth;
    @Value("${spring.mail.properties.mail.smtp.starttls.enable}") private String starttls;
    @Value("${spring.mail.properties.mail.smtp.connectiontimeout}") private int connectionTimeout;
    @Value("${spring.mail.properties.mail.smtp.timeout}") private int timeout;
    @Value("${spring.mail.properties.mail.smtp.writetimeout}") private int writeTimeout;

    private JavaMailSender mailSenderInstance; // ✅ Store instance

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
        props.put("mail.debug", "true");

        this.mailSenderInstance = mailSender; // ✅ Store for later test
        return mailSender;
    }

    @Bean
    public Scheduler emailScheduler() {
        return Schedulers.boundedElastic();
    }

    // ✅ FIXED - Test after bean creation to avoid circular dependency
    @PostConstruct
    public void verifyEmailConfiguration() {
        log.info("╔════════════════════════════════════════════════════════════╗");
        log.info("║           EMAIL CONFIGURATION VERIFICATION                 ║");
        log.info("╠════════════════════════════════════════════════════════════╣");
        log.info("║  Host: {}║", String.format("%-51s", host));
        log.info("║  Port: {}║", String.format("%-51s", port));
        log.info("║  Protocol: {}║", String.format("%-47s", protocol));
        log.info("║  Username: {}║", String.format("%-47s", HelperUtils.maskEmail(username)));
        log.info("║  From Address: {}║", String.format("%-43s", HelperUtils.maskEmail(fromAddress)));
        log.info("║  SMTP Auth: {}║", String.format("%-46s", smtpAuth));
        log.info("║  StartTLS: {}║", String.format("%-47s", starttls));
        log.info("╠════════════════════════════════════════════════════════════╣");

        try {
            // ✅ Test by actually trying to connect
            JavaMailSenderImpl testSender = new JavaMailSenderImpl();
            testSender.setHost(host);
            testSender.setPort(port);
            testSender.setUsername(username);
            testSender.setPassword(password);

            Properties props = testSender.getJavaMailProperties();
            props.put("mail.smtp.auth", smtpAuth);
            props.put("mail.smtp.starttls.enable", starttls);
            props.put("mail.smtp.connectiontimeout", "5000");
            props.put("mail.smtp.timeout", "5000");

            testSender.testConnection();
            log.info("║  Status: ✅ CONNECTION SUCCESSFUL                         ║");
        } catch (Exception e) {
            log.error("║  Status: ❌ CONNECTION FAILED                             ║");
            String errorMsg = e.getMessage();
            if (errorMsg != null && errorMsg.length() > 49) {
                errorMsg = errorMsg.substring(0, 49);
            }
            log.error("║  Error: {}║", String.format("%-49s", errorMsg == null ? "Unknown error" : errorMsg));
            log.error("║  Full Error: {}", e.getMessage());
            log.error("╠════════════════════════════════════════════════════════════╣");
            log.error("║  ⚠️  CRITICAL: Email service is NOT operational!         ║");
            log.error("║  ⚠️  Super Admin passwords will be logged to console!    ║");
            log.error("║                                                            ║");
            log.error("║  Common Gmail Issues:                                      ║");
            log.error("║  1. Not using App Password (must enable 2FA first)        ║");
            log.error("║  2. 'Less secure app access' disabled                     ║");
            log.error("║  3. Wrong credentials                                     ║");
            log.error("║  4. Firewall blocking port 587                            ║");
        }
        log.info("╚════════════════════════════════════════════════════════════╝");
    }

    @Bean
    public String emailFromAddress() {
        return fromAddress;
    }
}