package com.techStack.authSys.service.bootstrap;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class TransactionalService {

    private final List<Runnable> rollbackActions = new ArrayList<>();
    private boolean transactionFailed = false;

    /**
     * Register a rollback action to be executed if transaction fails
     */
    public void registerRollback(Runnable rollbackAction) {
        rollbackActions.add(rollbackAction);
    }

    /**
     * Mark transaction as failed
     */
    public void markFailed() {
        this.transactionFailed = true;
    }

    /**
     * Execute all rollback actions if transaction failed
     */
    public Mono<Void> executeRollbackIfNeeded() {
        if (transactionFailed) {
            log.warn("⚠️ Executing rollback for {} actions", rollbackActions.size());
            return Flux.fromIterable(rollbackActions)
                    .flatMap(action -> {
                        try {
                            action.run();
                            return Mono.empty();
                        } catch (Exception e) {
                            log.error("❌ Rollback action failed: {}", e.getMessage());
                            return Mono.empty();
                        }
                    })
                    .then();
        }
        return Mono.empty();
    }

    /**
     * Clear rollback actions after successful commit
     */
    public void clearRollbackActions() {
        rollbackActions.clear();
        transactionFailed = false;
    }
}
