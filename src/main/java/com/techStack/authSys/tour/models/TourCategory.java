package com.techStack.authSys.tour.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum TourCategory {
    SAFARI("Safari"),
    DAY_TRIP("Day Trip"),
    CULTURAL("Cultural Experience"),
    ADVENTURE("Adventure"),
    BEACH("Beach & Coast"),
    MOUNTAIN("Mountain & Hiking"),
    WILDLIFE("Wildlife"),
    CITY_TOUR("City Tour"),
    PHOTOGRAPHY("Photography Tour"),
    FAMILY("Family Tour"),
    LUXURY("Luxury experience"),
    BUDGET("Budget"),

    HONEYMOON("Honey Moon"),
    GROUP("group"),
    CRUISE("cruise");


    private final String displayName;
}
