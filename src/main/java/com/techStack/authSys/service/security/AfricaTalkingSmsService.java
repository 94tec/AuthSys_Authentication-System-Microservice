package com.techStack.authSys.service.security;

import com.techStack.authSys.config.intergration.AfricaTalkingProperties;
import com.techStack.authSys.repository.notification.SmsService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import static com.techStack.authSys.util.validation.HelperUtils.maskOtp;
import static com.techStack.authSys.util.validation.HelperUtils.maskPhone;

@Slf4j
@Service
@RequiredArgsConstructor
public class AfricaTalkingSmsService implements SmsService {

    private final WebClient.Builder webClientBuilder;
    private final AfricaTalkingProperties props;
    private final Clock clock;

    @Value("${sms.provider.enabled:false}")
    private boolean smsEnabled;

    @Override
    public Mono<Void> sendOtp(String phoneNumber, String otp) {

        Instant now = clock.instant();

        if (!smsEnabled) {
            logOtpToConsole(phoneNumber, otp, now, "OTP");
            return Mono.empty();
        }

        if (props.getApiKey() == null || props.getApiKey().isBlank()) {
            log.error("❌ Africa's Talking API key missing (sms.africastalking.apiKey)");
            logOtpToConsole(phoneNumber, otp, now, "OTP");
            return Mono.empty();
        }

        String message = String.format(
                "Your verification code is: %s. Valid for 10 minutes. Do not share this code with anyone.",
                otp
        );

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("username", props.getUsername());
        form.add("to", phoneNumber);
        form.add("message", message);

        // only include from if set
        if (props.getFrom() != null && !props.getFrom().isBlank()) {
            form.add("from", props.getFrom());
        }

        return webClientBuilder.build()
                .post()
                .uri(props.getSmsUrl())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .header("apiKey", props.getApiKey())
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(String.class) // AfricaTalking response is not consistent sometimes
                .timeout(Duration.ofSeconds(8))
                .doOnNext(raw -> log.info("📨 AfricaTalking SMS response: {}", raw))
                .then()
                .retryWhen(
                        Retry.backoff(2, Duration.ofMillis(250))
                                .maxBackoff(Duration.ofSeconds(2))
                )
                .doOnSuccess(v ->
                        log.info("✅ OTP SMS sent to {} at {} (otp={})",
                                maskPhone(phoneNumber),
                                now,
                                maskOtp(otp)
                        )
                )
                .doOnError(ex ->
                        log.error("❌ Failed sending OTP SMS to {} (otp={}): {}",
                                maskPhone(phoneNumber),
                                maskOtp(otp),
                                ex.getMessage(),
                                ex
                        )
                );
    }

    /* =========================
       Logging Helpers
       ========================= */

    private void logOtpToConsole(String phoneNumber, String otp, Instant timestamp, String type) {
        log.info("╔════════════════════════════════════════════════════════╗");
        log.info("║  📱 SMS OTP (DEVELOPMENT MODE)                        ║");
        log.info("╠════════════════════════════════════════════════════════╣");
        log.info("║  Phone:  {}║", String.format("%-45s", phoneNumber));
        log.info("║  Code:   {}║", String.format("%-45s", otp));
        log.info("║  Type:   {}║", String.format("%-45s", type));
        log.info("║  Sent:   {}║", String.format("%-45s", timestamp));
        log.info("╚════════════════════════════════════════════════════════╝");
    }
}
