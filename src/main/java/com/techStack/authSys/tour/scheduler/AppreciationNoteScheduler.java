package com.techStack.authSys.tour.scheduler;

import com.techStack.authSys.tour.models.*;
import com.techStack.authSys.tour.notification.EnquiryNotificationService;
import com.techStack.authSys.tour.repository.EnquiryEventRepository;
import com.techStack.authSys.tour.repository.TourEnquiryRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class AppreciationNoteScheduler {

    private final TourEnquiryRepository enquiryRepository;
    private final EnquiryEventRepository eventRepository;
    private final EnquiryNotificationService notificationService;
    private final TransactionTemplate transactionTemplate;

    /** Runs daily at 07:00 — marks finished trips COMPLETED and sends the appreciation note. */
    @Scheduled(cron = "0 0 7 * * *")
    public void processCompletedTrips() {
        List<TourEnquiry> due = enquiryRepository.findEligibleForAppreciation(LocalDate.now());
        for (TourEnquiry e : due) {
            try {
                String tourName = transactionTemplate.execute(status -> {
                    e.setStatus(TourEnquiryStatus.COMPLETED);
                    e.setAppreciationSentAt(Instant.now());
                    enquiryRepository.save(e);

                    String name = e.getTour().getName(); // still inside the transaction here

                    eventRepository.save(EnquiryEvent.builder()
                            .enquiry(e)
                            .actorType(ActorType.SYSTEM)
                            .eventType(ActivityAction.APPRECIATION_SENT)
                            .fromStatus(TourEnquiryStatus.CONVERTED)
                            .toStatus(TourEnquiryStatus.COMPLETED)
                            .details("Appreciation note sent after travel end date")
                            .build());

                    return name;
                });
                notificationService.sendAppreciationNote(e, tourName).block();
            } catch (Exception ex) {
                log.error("Failed to process appreciation note for enquiry {}", e.getId(), ex);
            }
        }
    }
}