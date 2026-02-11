package com.techStack.authSys.config.core;

import org.jetbrains.annotations.NotNull;
import org.springframework.boot.context.properties.ConfigurationPropertiesBinding;
import org.springframework.core.convert.converter.Converter;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

@Component
@ConfigurationPropertiesBinding
public class PatternConverter implements Converter<String, Pattern> {
    @Override
    public Pattern convert(@NotNull String source) {
        return Pattern.compile(source);
    }
}
