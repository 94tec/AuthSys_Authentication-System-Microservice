package com.techStack.authSys.security.audit;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.Map;

/**
 * Loose, schema-agnostic shape for collections that don't have a dedicated
 * DTO. `label` is a best-effort pick of whatever field looks like the
 * "headline" for this document (action/eventType/operation/status — first
 * match wins). `fields` carries everything else so the detail view can show
 * it without the backend needing to know each collection's exact shape.
 */
@Getter
@Setter
@NoArgsConstructor
public class GenericLogDTO {
    private String id;
    private String label;
    private String severity;
    private Instant timestamp;
    private String userId;
    private Map<String, Object> fields;
}