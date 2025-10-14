import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;

import java.util.concurrent.TimeUnit;

@Bean
@ConfigurationProperties(prefix = "permissions.cache")
public CacheManager permissionCacheManager() {
    CaffeineCacheManager cacheManager = new CaffeineCacheManager("permissions");
    cacheManager.setCaffeine(Caffeine.newBuilder()
            .expireAfterWrite(5, TimeUnit.MINUTES)
            .maximumSize(1000));
    return cacheManager;
}

public void main() {
}