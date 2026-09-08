package com.techStack.authSys.authorization.constants;

import java.util.Set;

public final class SecurityConstants {

    private SecurityConstants(){}

    public static final Set<String> VALID_NAMESPACES = Set.of(
            "traveler",
            "booking",
            "tour",
            "enquiry",
            "enquire-button.tsx",
            "destination",
            "itinerary",
            "guide",
            "vehicle",
            "supplier",
            "payment",
            "review",
            "report",
            "user",
            "system"
    );
}
