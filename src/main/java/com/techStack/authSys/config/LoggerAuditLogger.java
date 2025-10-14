package com.techStack.authSys.config;

public interface LoggerAuditLogger {
    void log(boolean granted, String message);
}
