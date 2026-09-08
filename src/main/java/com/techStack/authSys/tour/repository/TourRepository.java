package com.techStack.authSys.tour.repository;

import com.techStack.authSys.tour.models.Tour;
import com.techStack.authSys.tour.models.TourCategory;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
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

    // TourRepository
    Optional<Tour> findByIdAndDeletedFalse(UUID id);

    @Query("""
    select t from Tour t
    left join fetch t.highlights
    left join fetch t.itinerary
    left join fetch t.inclusions
    left join fetch t.exclusions
    left join fetch t.requirements
    left join fetch t.galleryImages
    where t.id = :id and t.deleted = false
    """)
    Optional<Tour> findDetailedByIdAndDeletedFalse(@Param("id") UUID id);

    Page<Tour> findAllByDeletedFalseAndActiveTrue(Pageable pageable);

    Page<Tour> findAllByDeletedFalseAndActiveTrueAndCategory(
            TourCategory category,
            Pageable pageable
    );

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
    Page<Tour> searchTours(
            @Param("query") String query,
            Pageable pageable
    );

    @Query("""
            SELECT COUNT(t)
            FROM Tour t
            WHERE t.deleted = false
              AND t.active = true
            """)
    long countActiveTours();

    long countByDeletedFalse();

    @Query("""
    SELECT t FROM Tour t
    WHERE t.deleted = false
      AND t.active = true
      AND (:category IS NULL OR t.category = :category)
      AND (:country IS NULL OR LOWER(t.country) = :country)
      AND (:destination IS NULL OR LOWER(t.destination) = :destination)
    """)
    Page<Tour> findFiltered(
            @Param("category") TourCategory category,
            @Param("country") String country,
            @Param("destination") String destination,
            Pageable pageable
    );

}
