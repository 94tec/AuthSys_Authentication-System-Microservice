package com.techStack.authSys.models;

import com.google.cloud.Timestamp;
import com.google.cloud.spring.data.firestore.Document;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.data.annotation.Id;

@Getter
@Setter
@NoArgsConstructor
@Document(collectionName = "audit_logs") // Firestore collection
public class AuditLog {

    @Id
    private String id; // Firestore uses String IDs

    @NotNull(message = "User ID is required")
    private String userId; // Firestore does not support ManyToOne relationships

    @PastOrPresent(message = "Timestamp cannot be in the future")
    private Timestamp createdAt;

    @NotNull(message = "Action type is required")
    private ActionType actionType;

    @NotBlank(message = "IP address cannot be blank")
    @Pattern(regexp = "^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){1,6}(:[0-9A-Fa-f]{1,6})?)|(([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,5})?)|(([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4})?)|(([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,3})?)|(([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,2})?)|([0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,7}|:))|(:((:[0-9A-Fa-f]{1,4}){1,7}|:))|(([0-9]{1,3}\\.){3}[0-9]{1,3}))$",
            message = "Invalid IP address format (IPv4 or IPv6 supported)")
    private String ipAddress;

    @Size(max = 512, message = "Details must be less than 512 characters")
    private String details;

    // Auto-set timestamp
    public AuditLog(String userId, ActionType actionType, String ipAddress, String details) {
        this.userId = userId;
        this.actionType = actionType;
        this.ipAddress = ipAddress;
        this.details = details;
        this.createdAt = Timestamp.now();
    }
}
