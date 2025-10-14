package com.techStack.authSys.models;

import com.techStack.authSys.service.EncryptionService;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import java.time.Instant;
import java.util.Date;

@Getter
@Setter
@ToString
public class BlacklistEntry {

    private String ipAddress;  // Encrypted
    private String reason;     // Encrypted
    private Date expiration;
    private Date createdAt;

    private final EncryptionService encryptionService;

    public BlacklistEntry(String ipAddress, String reason, Instant expiration, EncryptionService encryptionService) {
        this.encryptionService = encryptionService; // Inject EncryptionService instance
        this.ipAddress = encryptionService.encrypt(ipAddress);
        this.reason = encryptionService.encrypt(reason);
        this.expiration = Date.from(expiration);
        this.createdAt = Date.from(Instant.now());
    }

    public String getDecryptedIpAddress() {
        return encryptionService.decrypt(this.ipAddress);
    }

    public String getDecryptedReason() {
        return encryptionService.decrypt(this.reason);
    }
}
