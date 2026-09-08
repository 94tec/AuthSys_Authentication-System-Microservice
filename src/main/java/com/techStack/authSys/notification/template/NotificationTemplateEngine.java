package com.techStack.authSys.notification.template;

import com.techStack.authSys.notification.models.NotificationChannel;
import com.techStack.authSys.notification.models.NotificationContext;
import com.techStack.authSys.notification.models.NotificationType;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

/**
 * Simple {{variable}} template engine for notification content.
 *
 * Loads templates from:
 *   resources/templates/email/{TYPE}.html
 *   resources/templates/sms/{TYPE}.txt
 *   resources/templates/whatsapp/{TYPE}.txt
 *
 * Variables are substituted using {{variableName}} syntax.
 * Unknown variables are left as-is (no explosion on missing keys).
 *
 * Why not Thymeleaf/Freemarker?
 * Notification templates are plain text / simple HTML.
 * A full template engine adds classpath complexity for minimal gain.
 * This can be swapped in Phase 3 if templates grow complex.
 */
@Slf4j
@Component
public class NotificationTemplateEngine {

    private static final DateTimeFormatter DATE_FMT =
        DateTimeFormatter.ofPattern("EEEE, dd MMMM yyyy");

    private static final NumberFormat CURRENCY_FMT =
        NumberFormat.getNumberInstance(Locale.UK); // comma separator: 5,000

    /**
     * Render the subject line for an email notification.
     * Subject lines are short strings, not file-based.
     */
    public String renderSubject(NotificationType type, NotificationContext ctx) {
        return switch (type) {
            case BOOKING_CREATED    -> "We've received your booking — " + ctx.getTourName();
            case BOOKING_CONFIRMED  -> "Booking Confirmed ✓ — " + ctx.getTourName();
            case BOOKING_CANCELLED  -> "Your booking has been cancelled — " + ctx.getTourName();
            case BOOKING_COMPLETED  -> "Hope you enjoyed it! — " + ctx.getTourName();
            case BOOKING_REMINDER   -> "Your enquire-button.tsx is tomorrow — " + ctx.getTourName();
            case PAYMENT_RECEIVED   -> "Payment received — KES " + formatAmount(ctx.getPaymentAmount());
            case PAYMENT_FAILED     -> "Payment unsuccessful — please try again";
            case PAYMENT_REFUNDED   -> "Refund processed — " + ctx.getTourName();
            case ACCOUNT_APPROVED   -> "Your Damuchi Safaris account is ready";
            case ACCOUNT_REJECTED   -> "Update on your account application";
            case WELCOME            -> "Welcome to Damuchi Safaris, " + ctx.getCustomerName() + "!";
            case PASSWORD_RESET     -> "Reset your Damuchi Safaris password";
            case PROMOTIONAL        -> "New tours just for you — Damuchi Safaris";
            case REVIEW_REQUEST     -> "How was your " + ctx.getTourName() + " experience?";
        };
    }

    /**
     * Render the message body for a given channel and notification type.
     * Loads the template file then substitutes context variables.
     */
    public String renderBody(NotificationType type, NotificationChannel channel,
                             NotificationContext ctx) {
        String template = loadTemplate(type, channel);
        return substitute(template, buildVariables(ctx));
    }

    // ── Template loading ──────────────────────────────────────────────────────

    private String loadTemplate(NotificationType type, NotificationChannel channel) {
        String folder    = channel == NotificationChannel.EMAIL ? "email" : (
                           channel == NotificationChannel.SMS ? "sms" : "whatsapp");
        String extension = channel == NotificationChannel.EMAIL ? ".html" : ".txt";
        String path      = "templates/" + folder + "/" + type.name().toLowerCase() + extension;

        try {
            ClassPathResource resource = new ClassPathResource(path);
            return resource.getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            log.warn("Template not found: {} — using fallback", path);
            return buildFallback(type, channel, path);
        }
    }

    /**
     * Fallback template when a file is missing.
     * Returns a minimal but functional message so notifications
     * still go out even if a template hasn't been created yet.
     */
    private String buildFallback(NotificationType type, NotificationChannel channel, String path) {
        if (channel == NotificationChannel.EMAIL) {
            return "<p>Hello {{customerName}},</p>"
                + "<p>This is a notification from Damuchi Safaris regarding your "
                + type.getDisplayName().toLowerCase() + ".</p>"
                + "<p>[Template missing: " + path + "]</p>"
                + "<p>The Damuchi Safaris Team</p>";
        }
        return "Damuchi Safaris: {{customerName}}, "
            + type.getDisplayName() + ". "
            + "[Template missing: " + path + "]";
    }

    // ── Variable substitution ─────────────────────────────────────────────────

    private Map<String, String> buildVariables(NotificationContext ctx) {
        Map<String, String> vars = new HashMap<>();

        // Recipient
        vars.put("customerName",      safe(ctx.getCustomerName()));
        vars.put("customerEmail",     safe(ctx.getCustomerEmail()));
        vars.put("customerPhone",     safe(ctx.getCustomerPhone()));

        // Booking
        vars.put("bookingId",         ctx.getBookingId() != null
            ? ctx.getBookingId().toString().substring(0, 8).toUpperCase() : "");
        vars.put("tourName",          safe(ctx.getTourName()));
        vars.put("tourDate",          ctx.getTourDate() != null
            ? ctx.getTourDate().format(DATE_FMT) : "");
        vars.put("travelerCount",     ctx.getTravelerCount() != null
            ? ctx.getTravelerCount().toString() : "");
        vars.put("totalPrice",        formatAmount(ctx.getTotalPrice()));
        vars.put("currency",          safe(ctx.getCurrency()));
        vars.put("cancellationReason",safe(ctx.getCancellationReason()));
        vars.put("paymentReference",  safe(ctx.getPaymentReference()));

        // Payment
        vars.put("paymentAmount",     formatAmount(ctx.getPaymentAmount()));
        vars.put("mpesaReceiptNumber",safe(ctx.getMpesaReceiptNumber()));
        vars.put("paymentFailureReason", safe(ctx.getPaymentFailureReason()));

        // Account
        vars.put("rejectionReason",   safe(ctx.getRejectionReason()));
        vars.put("passwordResetUrl",  safe(ctx.getPasswordResetUrl()));

        // Branding
        vars.put("companyName",       "Damuchi Safaris");
        vars.put("supportEmail",      "support@damuchisafaris.co.ke");
        vars.put("websiteUrl",        "https://damuchisafaris.co.ke");
        vars.put("bookingPortalUrl",  "https://damuchisafaris.co.ke/my-bookings");

        return vars;
    }

    private String substitute(String template, Map<String, String> vars) {
        String result = template;
        for (Map.Entry<String, String> entry : vars.entrySet()) {
            result = result.replace("{{" + entry.getKey() + "}}", entry.getValue());
        }
        return result;
    }

    private String safe(String value) {
        return value != null ? value : "";
    }

    private String formatAmount(java.math.BigDecimal amount) {
        if (amount == null) return "";
        return CURRENCY_FMT.format(amount);
    }
}
