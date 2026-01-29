package com.techStack.authSys.config.observability;

public interface LoggerAuditLogger {
    void log(boolean granted, String message);
}
