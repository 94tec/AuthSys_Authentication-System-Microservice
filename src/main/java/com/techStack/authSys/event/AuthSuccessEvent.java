package com.techStack.authSys.event;


import com.techStack.authSys.models.user.User;
import lombok.Getter;
import org.springframework.context.ApplicationEvent;

@Getter
public class AuthSuccessEvent extends ApplicationEvent {
    private final User user;
    private final String ipAddress;

    public AuthSuccessEvent(User user, String ipAddress) {
        super(user);
        this.user = user;
        this.ipAddress = ipAddress;
    }
}
