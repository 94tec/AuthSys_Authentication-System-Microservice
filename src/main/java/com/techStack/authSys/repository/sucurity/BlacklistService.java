package com.techStack.authSys.repository.sucurity;

import reactor.core.publisher.Mono;

public interface BlacklistService {

    /**
     * Checks if an IP address is blacklisted.
     *
     * @param ipAddress The IP address to check.
     * @return Mono<Boolean> indicating whether the IP is blacklisted.
     */
    Mono<Boolean> isBlacklisted(String ipAddress);

    /**
     * Adds an IP address to the blacklist with a reason and expiration duration.
     *
     * @param ipAddress     The IP address to blacklist.
     * @param reason        The reason for blacklisting.
     * @param durationHours The duration (in hours) for which the IP should remain blacklisted.
     * @return Mono<Void> indicating completion.
     */
    Mono<Void> addToBlacklist(String ipAddress, String reason, int durationHours);

    /**
     * Removes an IP address from the blacklist.
     *
     * @param ipAddress The IP address to remove.
     * @return Mono<Void> indicating completion.
     */
    Mono<Void> removeFromBlacklist(String ipAddress);

    /**
     * Blacklists an IP address for suspicious activity using a default duration.
     *
     * @param ipAddress The IP address to blacklist.
     * @return Mono<Void> indicating completion.
     */
    Mono<Void> blacklistIp(String ipAddress);
}

