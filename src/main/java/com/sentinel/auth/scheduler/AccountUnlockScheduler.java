package com.sentinel.auth.scheduler;

import com.sentinel.auth.enums.UserStatus;
import com.sentinel.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

/**
 * Scheduled job para desbloquear cuentas cuyo período de bloqueo ha expirado.
 * Se ejecuta cada 5 minutos.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class AccountUnlockScheduler {

    private final UserRepository userRepository;

    /**
     * Desbloquea cuentas cuyo período de bloqueo ha expirado.
     * Cron: Cada 5 minutos
     */
    @Scheduled(cron = "0 */5 * * * *")
    @Transactional
    public void unlockExpiredAccounts() {
        log.debug("Checking for expired account locks");
        
        try {
            int unlockedCount = userRepository.unlockExpiredAccounts(
                UserStatus.ACTIVE,
                UserStatus.LOCKED,
                LocalDateTime.now()
            );
            
            if (unlockedCount > 0) {
                log.info("Unlocked {} accounts with expired locks", unlockedCount);
            }
        } catch (Exception e) {
            log.error("Error during account unlock: {}", e.getMessage());
        }
    }
}