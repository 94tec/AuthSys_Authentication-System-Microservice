package com.techStack.authSys.config.intergration;

import lombok.extern.slf4j.Slf4j;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.thymeleaf.spring6.SpringTemplateEngine;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;
import org.thymeleaf.templateresolver.ITemplateResolver;
import reactor.core.scheduler.Scheduler;
import reactor.core.scheduler.Schedulers;

/**
 * Email rendering infrastructure (Thymeleaf + scheduler).
 *
 * Gmail SMTP / JavaMailSender removed — delivery is handled by BrevoClient.
 */
@Slf4j
@Configuration
public class EmailConfig {

    /** Scheduler used to render templates off the event loop. */
    @Bean
    public Scheduler emailScheduler() {
        return Schedulers.boundedElastic();
    }

    @Bean
    public SpringTemplateEngine emailTemplateEngine() {
        SpringTemplateEngine templateEngine = new SpringTemplateEngine();
        templateEngine.setTemplateResolver(emailTemplateResolver());
        templateEngine.setMessageSource(emailMessageSource());
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
        source.setBasename("i18n/email-messages");
        source.setDefaultEncoding("UTF-8");
        return source;
    }
}