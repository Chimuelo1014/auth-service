package com.sentinel.auth.repository;

import com.sentinel.auth.entity.PasswordResetTokenEntity;
import com.sentinel.auth.enums.TokenStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetTokenEntity, UUID> {

    Optional<PasswordResetTokenEntity> findByTokenAndStatus(String token, TokenStatus status);

    @Query("SELECT t FROM PasswordResetTokenEntity t WHERE t.userId = :userId")
    List<PasswordResetTokenEntity> findByUserId(@Param("userId") UUID userId);

    @Modifying
    @Query("DELETE FROM PasswordResetTokenEntity t WHERE t.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE PasswordResetTokenEntity t SET t.status = :status WHERE t.userId = :userId AND t.status = :activeStatus")
    void revokeAllUserTokens(
        @Param("userId") UUID userId, 
        @Param("status") TokenStatus status, 
        @Param("activeStatus") TokenStatus activeStatus
    );
}
