package com.techStack.authSys.tour.notification;

import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Mirrors EmailServiceInstance's shape: a concrete service (not yet promoted
 * to a shared interface) exposing templated-send methods for use across the
 * notification package.
 */
public interface WhatsAppService {

    /**
     * Sends a pre-approved WhatsApp Business template message.
     *
     * @param toPhone      E.164 format, e.g. "+254712345678" — validated before this is called
     * @param templateName must already be approved by Meta for your WhatsApp Business Account
     * @param vars         template parameter values, in the order the template expects them
     */
    Mono<Void> sendTemplatedMessage(String toPhone, String templateName, Map<String, Object> vars);
}