package com.techStack.authSys.tour.models;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum TourDifficulty {
    EASY("Easy — suitable for all ages and fitness levels"),
    MODERATE("Moderate — some walking and activity required"),
    CHALLENGING("Challenging — good fitness level recommended"),
    STRENUOUS("Strenuous — high fitness level required");

    private final String description;
}
