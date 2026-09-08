package com.techStack.authSys.availability.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;

/**
 * Summary returned after a bulk slot creation.
 * Tells the client how many were created vs skipped.
 */
@Data
@Builder
public class BulkCreateResult {

    private int created;   // slots successfully created
    private int skipped;   // dates already had a slot or were in the past
    private int total;     // dates evaluated in the range

    private List<AvailabilityResponse> createdSlots;
    private List<String>               skippedDates;  // ISO dates skipped
}
