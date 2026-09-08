package com.techStack.authSys.customer.repository;

import com.techStack.authSys.customer.models.DocumentType;
import com.techStack.authSys.customer.models.TravelDocument;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * TravelDocumentRepository
 *
 * Caller map:
 *   CustomerService.getDocuments()        → findByCustomerProfileIdAndDeletedFalse
 *   CustomerService.addDocument()         → save()
 *   CustomerService.updateDocument()      → findByIdAndCustomerProfileIdAndDeletedFalse
 *   CustomerService.deleteDocument()      → findByIdAndCustomerProfileIdAndDeletedFalse, save()
 *   CustomerService.setPrimaryDocument()  → clearPrimaryForProfile, save()
 *   CustomerService.getPrimaryDocument()  → findPrimaryByCustomerProfileId
 */
@Repository
public interface TravelDocumentRepository extends JpaRepository<TravelDocument, UUID> {

    /**
     * All non-deleted documents for a customer profile.
     * Used by getDocuments() — customer's saved document list.
     */
    List<TravelDocument> findByCustomerProfileIdAndDeletedFalse(UUID customerProfileId);

    /**
     * All documents of a specific type for a customer.
     * e.g. all passports — used to warn about expiry before international bookings.
     */
    List<TravelDocument> findByCustomerProfileIdAndDocumentTypeAndDeletedFalse(
            UUID customerProfileId, DocumentType documentType);

    /**
     * Single non-deleted document scoped to a customer profile — IDOR guard.
     * Used for update and delete — customer cannot modify another customer's documents.
     */
    Optional<TravelDocument> findByIdAndCustomerProfileIdAndDeletedFalse(
            UUID id, UUID customerProfileId);

    /**
     * The customer's primary document — used to pre-fill booking form.
     */
    @Query("""
            SELECT d FROM TravelDocument d
            WHERE d.customerProfile.id = :profileId
              AND d.primaryDocument    = true
              AND d.deleted            = false
            """)
    Optional<TravelDocument> findPrimaryByCustomerProfileId(
            @Param("profileId") UUID profileId);

    /**
     * Clears the primaryDocument flag for ALL documents of a profile.
     * Called before setting a new primary — ensures only one primary exists.
     */
    @Modifying
    @Query("""
            UPDATE TravelDocument d
            SET d.primaryDocument = false
            WHERE d.customerProfile.id = :profileId
            """)
    void clearPrimaryForProfile(@Param("profileId") UUID profileId);

    /**
     * Count non-deleted documents for a profile — used in profile summary.
     */
    long countByCustomerProfileIdAndDeletedFalse(UUID customerProfileId);
}
