package com.techStack.authSys.customer.repository;

import com.techStack.authSys.customer.models.CustomerProfile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * CustomerProfileRepository
 *
 * Caller map:
 *   CustomerService.getOrCreateProfile()  → findByCustomerId, save()
 *   CustomerService.updateProfile()       → findByCustomerIdAndDeletedFalse, save()
 *   CustomerService.getProfileById()      → findByIdAndDeletedFalse       (staff)
 *   CustomerService.searchCustomers()     → searchByEmailOrName            (MANAGER+)
 *   CustomerService.getAllCustomers()     → findAllByDeletedFalse          (ADMIN+)
 *   CustomerService.addToWishlist()       → findByCustomerIdAndDeletedFalse, save()
 *   CustomerService.removeFromWishlist()  → findByCustomerIdAndDeletedFalse, save()
 */
@Repository
public interface CustomerProfileRepository extends JpaRepository<CustomerProfile, UUID> {

    // ── Primary lookup — by Firebase UID ─────────────────────────────────────

    /**
     * Find profile by Firebase UID.
     * Used by getOrCreateProfile() — returns empty if profile hasn't been created yet.
     */
    Optional<CustomerProfile> findByCustomerId(String customerId);

    /**
     * Find non-deleted profile by Firebase UID.
     * Used by all update and wishlist operations.
     */
    Optional<CustomerProfile> findByCustomerIdAndDeletedFalse(String customerId);

    /**
     * Existence check — used in getOrCreateProfile() before creating.
     */
    boolean existsByCustomerId(String customerId);

    // ── Staff / admin reads ───────────────────────────────────────────────────

    /**
     * Single non-deleted profile by internal UUID.
     * Used by staff when viewing a specific customer (from a booking detail).
     */
    Optional<CustomerProfile> findByIdAndDeletedFalse(UUID id);

    /**
     * Paginated list of all non-deleted profiles — ADMIN view.
     */
    Page<CustomerProfile> findAllByDeletedFalse(Pageable pageable);

    /**
     * Case-insensitive search by email or name — staff customer lookup.
     * Used by MANAGER/ADMIN when searching for a customer from a booking.
     */
    @Query("""
            SELECT c FROM CustomerProfile c
            WHERE c.deleted = false
              AND (
                LOWER(c.email)     LIKE LOWER(CONCAT('%', :query, '%'))
                OR LOWER(c.firstName) LIKE LOWER(CONCAT('%', :query, '%'))
                OR LOWER(c.lastName)  LIKE LOWER(CONCAT('%', :query, '%'))
                OR LOWER(CONCAT(c.firstName, ' ', c.lastName))
                                   LIKE LOWER(CONCAT('%', :query, '%'))
              )
            ORDER BY c.lastName ASC
            """)
    Page<CustomerProfile> searchByEmailOrName(
            @Param("query") String query, Pageable pageable);

    /**
     * Count total non-deleted customer profiles — admin dashboard stat.
     */
    long countByDeletedFalse();
}
