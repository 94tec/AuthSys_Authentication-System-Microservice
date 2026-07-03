package com.techStack.authSys.tour.repository;

import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourCategory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface TourRepository extends JpaRepository<Tour, UUID> {

    Optional<Tour> findBySlugAndDeletedFalse(String slug);

    Optional<Tour> findByIdAndDeletedFalse(UUID id);

    Page<Tour> findAllByDeletedFalseAndActiveTrue(Pageable pageable);

    Page<Tour> findAllByDeletedFalseAndActiveTrueAndCategory(TourCategory category, Pageable pageable);

    List<Tour> findAllByDeletedFalseAndActiveTrueAndFeaturedTrue();

    boolean existsBySlug(String slug);

    boolean existsByNameIgnoreCase(String name);

    @Query("""
            SELECT t FROM Tour t
            WHERE t.deleted = false
              AND t.active = true
              AND (
                LOWER(t.name) LIKE LOWER(CONCAT('%', :query, '%'))
                OR LOWER(t.destination) LIKE LOWER(CONCAT('%', :query, '%'))
                OR LOWER(t.description) LIKE LOWER(CONCAT('%', :query, '%'))
              )
            """)
    Page<Tour> searchTours(@Param("query") String query, Pageable pageable);

    @Modifying
    @Query("UPDATE Tour t SET t.totalBookings = t.totalBookings + 1 WHERE t.id = :id")
    void incrementBookingCount(@Param("id") UUID id);

    @Query("SELECT COUNT(t) FROM Tour t WHERE t.deleted = false AND t.active = true")
    long countActiveTours();
}
