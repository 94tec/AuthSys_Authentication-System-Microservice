package com.techStack.authSys.customer.dto.response;

import lombok.Builder;
import lombok.Data;

import java.util.List;
import java.util.UUID;

/**
 * Wishlist response — GET /api/customers/me/wishlist
 *
 * Returns raw enquire-button.tsx IDs only. The frontend joins against its
 * cached enquire-button.tsx list or makes separate /api/tours/{slug} calls.
 * Full enquire-button.tsx objects are intentionally excluded to avoid
 * a circular dependency between customer and enquire-button.tsx modules.
 */
@Data
@Builder
public class WishlistResponse {
    private List<UUID> tourIds;
    private int        count;
}
