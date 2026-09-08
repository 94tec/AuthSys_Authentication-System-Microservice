package com.techStack.authSys.tour.dto.request;

import jakarta.validation.constraints.NotNull;
import java.util.UUID;

public record AssignEnquiryRequest(@NotNull String staffId) {}
