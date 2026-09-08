package com.techStack.authSys.config.intergration;

import com.techStack.authSys.common.util.HelperUtils;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.MessageSource;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Properties;

/**
 * Email Configuration
 *
 * Configures email service with SMTP settings.
 * Uses Clock for timestamp tracking and monitoring.
 */
@Configuration
@Slf4j
public class EmailConfig {

    /* =========================
       SMTP Configuration
       ========================= */

    @Value("${spring.mail.host}")
    private String host;

    @Value("${spring.mail.port}")
    private int port;

    @Value("${spring.mail.username}")
    private String username;

    @Value("${spring.mail.password}")
    private String password;

    @Value("${spring.mail.protocol:smtp}")
    private String protocol;

    @Value("${spring.mail.from:${spring.mail.username}}")
    private String fromAddress;

    /* =========================
       SMTP Properties
       ========================= */

    @Value("${spring.mail.properties.mail.smtp.auth:true}")
    private String smtpAuth;

    @Value("${spring.mail.properties.mail.smtp.starttls.enable:true}")
    private String starttls;

    @Value("${spring.mail.properties.mail.smtp.connectiontimeout:5000}")
    private int connectionTimeout;

    @Value("${spring.mail.properties.mail.smtp.timeout:5000}")
    private int timeout;

    @Value("${spring.mail.properties.mail.smtp.writetimeout:5000}")
    private int writeTimeout;

    @Value("${spring.mail.properties.mail.debug:false}")
    private boolean mailDebug;

    /* =========================
       Additional Settings
       ========================= */

    @Value("${spring.mail.test-connection:true}")
    private boolean testConnection;

    @Value("${spring.mail.default-encoding:UTF-8}")
    private String defaultEncoding;

    /* =========================
       Internal State
       ========================= */

    private JavaMailSender mailSenderInstance;
    @Getter
    private Instant configurationTime;
    @Getter
    private boolean connectionSuccessful = false;

    /* =========================
       Mail Sender Bean
       ========================= */

    /**
     * Configure JavaMailSender with SMTP settings
     */
    @Bean
    public JavaMailSender javaMailSender(Clock clock) {
        Instant startTime = clock.instant();

        log.info("📧 Configuring JavaMailSender at {}", startTime);

        JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
        mailSender.setHost(host);
        mailSender.setPort(port);
        mailSender.setUsername(username);
        mailSender.setPassword(password);
        mailSender.setProtocol(protocol);
        mailSender.setDefaultEncoding(defaultEncoding);

        // Configure SMTP properties
        Properties props = mailSender.getJavaMailProperties();
        props.put("mail.smtp.auth", smtpAuth);
        props.put("mail.smtp.starttls.enable", starttls);
        props.put("mail.smtp.connectiontimeout", connectionTimeout);
        props.put("mail.smtp.timeout", timeout);
        props.put("mail.smtp.writetimeout", writeTimeout);
        props.put("mail.debug", String.valueOf(mailDebug));

        // SSL/TLS properties
        props.put("mail.smtp.ssl.trust", host);
        props.put("mail.smtp.ssl.protocols", "TLSv1.2 TLSv1.3");

        this.mailSenderInstance = mailSender;
        this.configurationTime = startTime;

        Instant endTime = clock.instant();
        Duration duration = Duration.between(startTime, endTime);

        log.info("✅ JavaMailSender configured at {} (duration: {})", endTime, duration);

        return mailSender;
    }

    /* =========================
       Scheduler Bean
       ========================= */

    /**
     * Email scheduler for async operations
     */
    @Bean
    public Scheduler emailScheduler(Clock clock) {
        Instant now = clock.instant();

        log.info("⚙️ Creating email scheduler at {}", now);

        Scheduler scheduler = Schedulers.boundedElastic();

        log.info("✅ Email scheduler created at {}", now);

        return scheduler;
    }

    /* =========================
       From Address Bean
       ========================= */

    /**
     * Email from address
     */
    @Bean
    public String emailFromAddress() {
        return fromAddress;
    }

    @Bean
    public SpringTemplateEngine emailTemplateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(emailTemplateResolver());
        templateEngine.setMessageSource(emailMessageSource()); // i18n support
        return templateEngine;
    }

    private ITemplateResolver emailTemplateResolver() {
        ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
        resolver.setPrefix("classpath:/templates/emails/");
        resolver.setSuffix(".html");
        resolver.setTemplateMode("HTML");
        resolver.setCharacterEncoding("UTF-8");
        resolver.setCacheable(true);
        return resolver;
    }

    @Bean
    public MessageSource emailMessageSource() {
        ResourceBundleMessageSource source = new ResourceBundleMessageSource();
        source.setBasename("i18n/email-messages"); // optional, if you have email-specific messages
        source.setDefaultEncoding("UTF-8");
        return source;
    }

    /* =========================
       Configuration Verification
       ========================= */

    /**
     * Verify email configuration after bean creation
     */
    @PostConstruct
    public void verifyEmailConfiguration() {
        Instant verificationStart = Instant.now();

        log.info("╔════════════════════════════════════════════════════════════╗");
        log.info("║           EMAIL CONFIGURATION VERIFICATION                 ║");
        log.info("╠════════════════════════════════════════════════════════════╣");
        log.info("║  Verification Time: {}║",
                String.format("%-39s", verificationStart));
        log.info("║  Host: {}║",
                String.format("%-51s", host));
        log.info("║  Port: {}║",
                String.format("%-51s", port));
        log.info("║  Protocol: {}║",
                String.format("%-47s", protocol));
        log.info("║  Username: {}║",
                String.format("%-47s", HelperUtils.maskEmail(username)));
        log.info("║  From Address: {}║",
                String.format("%-43s", HelperUtils.maskEmail(fromAddress)));
        log.info("║  SMTP Auth: {}║",
                String.format("%-46s", smtpAuth));
        log.info("║  StartTLS: {}║",
                String.format("%-47s", starttls));
        log.info("║  Encoding: {}║",
                String.format("%-47s", defaultEncoding));
        log.info("║  Connection Timeout: {} ms║",
                String.format("%-36s", connectionTimeout));
        log.info("║  Read Timeout: {} ms║",
                String.format("%-41s", timeout));
        log.info("║  Write Timeout: {} ms║",
                String.format("%-40s", writeTimeout));
        log.info("╠════════════════════════════════════════════════════════════╣");

        if (testConnection) {
            testEmailConnection(verificationStart);
        } else {
            log.warn("║  ⚠️  Connection test DISABLED                             ║");
            log.info("╚════════════════════════════════════════════════════════════╝");
        }
    }

    /**
     * Test email connection
     */
    private void testEmailConnection(Instant startTime) {
        try {
            log.info("║  🔄 Testing SMTP connection...                            ║");

            JavaMailSenderImpl testSender = new JavaMailSenderImpl();
            testSender.setHost(host);
            testSender.setPort(port);
            testSender.setUsername(username);
            testSender.setPassword(password);
            testSender.setProtocol(protocol);

            Properties props = testSender.getJavaMailProperties();
            props.put("mail.smtp.auth", smtpAuth);
            props.put("mail.smtp.starttls.enable", starttls);
            props.put("mail.smtp.connectiontimeout", "5000");
            props.put("mail.smtp.timeout", "5000");
            props.put("mail.smtp.ssl.trust", host);

            testSender.testConnection();

            Instant endTime = Instant.now();
            Duration duration = Duration.between(startTime, endTime);

            connectionSuccessful = true;

            log.info("║  Status: ✅ CONNECTION SUCCESSFUL                         ║");
            log.info("║  Connection Time: {} ms║",
                    String.format("%-39s", duration.toMillis()));
            log.info("╠════════════════════════════════════════════════════════════╣");
            log.info("║  ✅ Email service is OPERATIONAL                          ║");

        } catch (Exception e) {
            Instant endTime = Instant.now();
            Duration duration = Duration.between(startTime, endTime);

            connectionSuccessful = false;

            log.error("║  Status: ❌ CONNECTION FAILED                             ║");
            log.error("║  Failed after: {} ms║",
                    String.format("%-41s", duration.toMillis()));

            String errorMsg = e.getMessage();
            if (errorMsg != null) {
                if (errorMsg.length() > 49) {
                    errorMsg = errorMsg.substring(0, 49) + "...";
                }
                log.error("║  Error: {}║",
                        String.format("%-50s", errorMsg));
            }

            log.error("╠════════════════════════════════════════════════════════════╣");
            log.error("║  ⚠️  CRITICAL: Email service is NOT operational!         ║");
            log.error("║  ⚠️  Notifications will fail!                            ║");
            log.error("║                                                            ║");

            logTroubleshootingSteps();

            if (log.isDebugEnabled()) {
                log.debug("Full error stack trace:", e);
            }
        }

        log.info("╚════════════════════════════════════════════════════════════╝");
    }

    /**
     * Log troubleshooting steps
     */
    private void logTroubleshootingSteps() {
        log.error("║  Common Issues & Solutions:                                ║");
        log.error("║                                                            ║");
        log.error("║  Gmail Users:                                              ║");
        log.error("║  1. Enable 2-Factor Authentication                         ║");
        log.error("║  2. Generate App Password (not your Gmail password)       ║");
        log.error("║  3. Use App Password in spring.mail.password              ║");
        log.error("║                                                            ║");
        log.error("║  General Troubleshooting:                                  ║");
        log.error("║  1. Check firewall rules for port {}║",
                String.format("%-28s", port));
        log.error("║  2. Verify SMTP host is correct                           ║");
        log.error("║  3. Confirm credentials are valid                         ║");
        log.error("║  4. Check if SMTP server requires SSL/TLS                 ║");
        log.error("║                                                            ║");
        log.error("║  Debug Steps:                                              ║");
        log.error("║  - Set spring.mail.properties.mail.debug=true             ║");
        log.error("║  - Check application logs for details                     ║");
        log.error("║  - Test connection manually with telnet                   ║");
    }

    /* =========================
       Health Check
       ========================= */

    /**
     * Email Health Indicator
     */
    @Bean
    public EmailHealthIndicator emailHealthIndicator(Clock clock) {
        return new EmailHealthIndicator(this, clock);
    }

    /**
     * Email Health Indicator implementation
     */
    public static class EmailHealthIndicator {

        private final EmailConfig emailConfig;
        private final Clock clock;

        public EmailHealthIndicator(EmailConfig emailConfig, Clock clock) {
            this.emailConfig = emailConfig;
            this.clock = clock;
        }

        /**
         * Check if email service is healthy
         */
        public boolean isHealthy() {
            return emailConfig.connectionSuccessful;
        }

        /**
         * Get email service status
         */
        public java.util.Map<String, Object> getStatus() {
            Instant statusTime = clock.instant();

            java.util.Map<String, Object> status = new java.util.HashMap<>();
            status.put("timestamp", statusTime.toString());
            status.put("healthy", isHealthy());
            status.put("host", emailConfig.host);
            status.put("port", emailConfig.port);
            status.put("protocol", emailConfig.protocol);
            status.put("from", HelperUtils.maskEmail(emailConfig.fromAddress));
            status.put("configuredAt", emailConfig.configurationTime != null ?
                    emailConfig.configurationTime.toString() : "unknown");

            if (emailConfig.configurationTime != null) {
                Duration uptime = Duration.between(emailConfig.configurationTime, statusTime);
                status.put("uptime", uptime.toString());
            }

            return status;
        }

        /**
         * Test email connection now
         */
        public boolean testConnection() {
            Instant testTime = clock.instant();

            try {
                JavaMailSenderImpl testSender = (JavaMailSenderImpl) emailConfig.mailSenderInstance;
                testSender.testConnection();

                log.info("✅ Email connection test passed at {}", testTime);
                return true;

            } catch (Exception e) {
                log.error("❌ Email connection test failed at {}: {}", testTime, e.getMessage());
                return false;
            }
        }
    }

}