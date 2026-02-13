package com.techStack.authSys.dto.sms;


import java.util.List;

public record AfricaTalkingSmsResponse(
        SmsMessageData SMSMessageData
) {
    public record SmsMessageData(
            List<Recipient> Recipients
    ) {}

    public record Recipient(
            String status,
            String number,
            String messageId,
            String cost
    ) {}
}

