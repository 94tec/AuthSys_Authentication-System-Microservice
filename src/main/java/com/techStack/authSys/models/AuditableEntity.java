package com.techStack.authSys.models;

import com.google.cloud.firestore.annotation.ServerTimestamp;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;

@Getter
@Setter
public abstract class AuditableEntity {

    private String createdBy;

    @ServerTimestamp
    private Instant createdDate;

    private String lastModifiedBy;

    @ServerTimestamp
    private Instant lastModifiedDate;
}
