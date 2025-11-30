package com.sentinel.auth.repository;

import com.sentinel.auth.entity.RefreshTokenEntity;
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
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, UUID> {

    /**
     * Find token by hash.
     */
    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    /**
     * Find all active tokens for a user.
     */
    @Query("SELECT t FROM RefreshTokenEntity t WHERE t.userId = :userId AND t.status = :status")
    List<RefreshTokenEntity> findActiveByUserId(
        @Param("userId") UUID userId,
        @Param("status") TokenStatus status
    );

    /**
     * Revoke all tokens for a user (logout from all devices).
     */
    @Modifying
    @Query("UPDATE RefreshTokenEntity t SET t.status = :revokedStatus, t.revokedAt = :now " +
           "WHERE t.userId = :userId AND t.status = :activeStatus")
    int revokeAllUserTokens(
        @Param("userId") UUID userId,
        @Param("revokedStatus") TokenStatus revokedStatus,
        @Param("activeStatus") TokenStatus activeStatus,
        @Param("now") LocalDateTime now
    );

    /**
     * Delete expired tokens (cleanup job).
     */
    @Modifying
    @Query("DELETE FROM RefreshTokenEntity t WHERE t.expiresAt < :now OR t.status = :expiredStatus")
    void deleteExpiredTokens(@Param("now") LocalDateTime now, @Param("expiredStatus") TokenStatus expiredStatus);

    /**
     * Count active tokens for a user.
     */
    @Query("SELECT COUNT(t) FROM RefreshTokenEntity t WHERE t.userId = :userId AND t.status = :status")
    long countActiveTokensByUserId(@Param("userId") UUID userId, @Param("status") TokenStatus status);
}