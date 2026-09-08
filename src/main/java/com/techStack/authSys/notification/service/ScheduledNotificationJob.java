package com.techStack.authSys.notification.service;

import com.techStack.authSys.booking.models.Booking;
import com.techStack.authSys.booking.models.BookingStatus;
import com.techStack.authSys.booking.repository.BookingRepository;
import com.techStack.authSys.booking.mapper.BookingMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.LocalDate;
import java.util.List;

/**
 * Scheduled jobs for notification delivery.
 *
 * Requires @EnableScheduling on your main application class or a @Configuration.
 *
 * Jobs:
 *   1. BOOKING_REMINDER  — runs daily at 08:00 Nairobi time (UTC+3 = 05:00 UTC)
 *      Finds all CONFIRMED bookings with tourDate = tomorrow and sends reminders.
 *
 *   2. Retry failed      — runs every 5 minutes
 *      Picks up FAILED/PENDING notification rows and retries them.
 *      Stops after notification.retry.max-attempts (default 3).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ScheduledNotificationJob {

    private final NotificationService notificationService;
    private final BookingRepository   bookingRepository;
    private final BookingMapper       bookingMapper;

    /**
     * Daily enquire-button.tsx reminder — 08:00 EAT (05:00 UTC).
     * Finds CONFIRMED bookings for tomorrow and fires BOOKING_REMINDER.
     */
    @Scheduled(cron = "0 0 5 * * *", zone = "UTC")
    public void sendTourReminders() {
        LocalDate tomorrow = LocalDate.now().plusDays(1);
        log.info("Running enquire-button.tsx reminder job for date: {}", tomorrow);

        List<Booking> upcoming = bookingRepository
            .findByStatusAndDeletedFalseOrderByCreatedDateDesc(BookingStatus.CONFIRMED)
            .stream()
            .filter(b -> tomorrow.equals(b.getTourDate()))
            .toList();

        log.info("Found {} confirmed bookings for tomorrow", upcoming.size());

        upcoming.forEach(booking ->
            notificationService.onBookingReminder(bookingMapper.toDTO(booking))
        );
    }

    /**
     * Retry failed notifications — every 5 minutes.
     */
    @Scheduled(fixedDelayString = "PT5M")
    public void retryFailedNotifications() {
        notificationService.retryFailed()
            .subscribe(count -> {
                if (count > 0) {
                    log.info("Retried {} failed notifications", count);
                }
            });
    }
}
