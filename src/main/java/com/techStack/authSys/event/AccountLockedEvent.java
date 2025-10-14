package com.techStack.authSys.event;


import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class AccountLockedEvent extends ApplicationEvent {
    private final String userId;

    public AccountLockedEvent(String userId) {
        super(userId);
        this.userId = userId;
    }
}

