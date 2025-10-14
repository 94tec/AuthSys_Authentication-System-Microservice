package com.techStack.authSys.event;

import com.techStack.authSys.models.User;
import org.springframework.context.ApplicationEvent;

public class FirstLoginEvent extends ApplicationEvent {
    private final User user;
    private final String ipAddress;

    public FirstLoginEvent(User user, String ipAddress) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
    }

    public User getUser() {
        return user;
    }

    public String getIpAddress() {
        return ipAddress;
    }
}

