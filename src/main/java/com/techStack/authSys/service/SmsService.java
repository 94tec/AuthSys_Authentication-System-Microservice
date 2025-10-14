package com.techStack.authSys.service;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;

@Service
public class SmsService {

    @Value("${twilio.account.sid}")
    private String accountSid;

    @Value("${twilio.auth.token}")
    private String authToken;

    @Value("${twilio.phone.number}")
    private String twilioPhoneNumber;

    @PostConstruct
    public void init() {
        // Initialize Twilio with your Account SID and Auth Token
        Twilio.init(accountSid, authToken);
    }

    public void sendSms(String toPhoneNumber, String messageBody) {
        try {
            // Create and send the SMS
            Message message = Message.creator(
                    new PhoneNumber(toPhoneNumber), // To phone number
                    new PhoneNumber(twilioPhoneNumber), // From Twilio phone number
                    messageBody // SMS body
            ).create();

            // Log the message SID for tracking
            System.out.println("SMS sent successfully! SID: " + message.getSid());
        } catch (Exception e) {
            System.err.println("Failed to send SMS: " + e.getMessage());
            throw new RuntimeException("Failed to send SMS", e);
        }
    }
}
