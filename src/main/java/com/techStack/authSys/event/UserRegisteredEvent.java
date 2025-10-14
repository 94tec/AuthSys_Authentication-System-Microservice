package com.techStack.authSys.event;

import com.techStack.authSys.models.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class UserRegisteredEvent extends ApplicationEvent {
    private final User user;
    private final String ipAddress;

    public UserRegisteredEvent(User user, String ipAddress) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
    }
}