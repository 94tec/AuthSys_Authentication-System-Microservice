package com.techStack.authSys.config;

import com.techStack.authSys.models.Permissions;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

@Component
public class PermissionConverter implements Converter<String, Permissions> {
    @Override
    public Permissions convert(String source) {
        return Permissions.valueOf(source.toUpperCase());
    }
}
