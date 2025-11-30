package com.sentinel.auth.repository;

import com.sentinel.auth.entity.UserEntity;
import com.sentinel.auth.enums.AuthProvider;
import com.sentinel.auth.enums.UserStatus;
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
public interface UserRepository extends JpaRepository<UserEntity, UUID> {

    /**
     * Find user by email address.
     */
    Optional<UserEntity> findByEmail(String email);

    /**
     * Find user by OAuth provider and provider user ID.
     */
    Optional<UserEntity> findByAuthProviderAndProviderUserId(
        AuthProvider authProvider, 
        String providerUserId
    );

    /**
     * Check if a user exists by email.
     */
    boolean existsByEmail(String email);

    /**
     * Find all users in a tenant.
     */
    List<UserEntity> findByTenantId(UUID tenantId);

    /**
     * Find users by status.
     */
    List<UserEntity> findByStatus(UserStatus status);

    /**
     * Find locked users whose lock has expired.
     */
    @Query("SELECT u FROM UserEntity u WHERE u.status = :status " +
           "AND u.lockedUntil IS NOT NULL AND u.lockedUntil < :now")
    List<UserEntity> findExpiredLockedUsers(
        @Param("status") UserStatus status,
        @Param("now") LocalDateTime now
    );

    /**
     * Unlock expired locked accounts (scheduled job).
     */
    @Modifying
    @Query("UPDATE UserEntity u SET u.status = :activeStatus, u.lockedUntil = NULL " +
           "WHERE u.status = :lockedStatus AND u.lockedUntil < :now")
    int unlockExpiredAccounts(
        @Param("activeStatus") UserStatus activeStatus,
        @Param("lockedStatus") UserStatus lockedStatus,
        @Param("now") LocalDateTime now
    );

    /**
     * Update last login timestamp.
     */
    @Modifying
    @Query("UPDATE UserEntity u SET u.lastLogin = :lastLogin WHERE u.id = :userId")
    void updateLastLogin(@Param("userId") UUID userId, @Param("lastLogin") LocalDateTime lastLogin);
}
