package com.techStack.authSys.tour.repository;

import com.techStack.authSys.tour.models.EnquiryEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface EnquiryEventRepository extends JpaRepository<EnquiryEvent, String> {
    List<EnquiryEvent> findAllByEnquiryIdOrderByCreatedAtDesc(UUID enquiryId);
}