package com.sentinel.auth.service.impl;

import com.sentinel.auth.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username:noreply@sentinel.com}")
    private String fromEmail;

    @Value("${app.name:Sentinel Security Scanner}")
    private String appName;

    @Async
    @Override
    public void sendPasswordResetEmail(String to, String resetUrl, String userName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(appName + " - Password Reset Request");
            message.setText(buildPasswordResetEmailBody(userName, resetUrl));
            
            mailSender.send(message);
            log.info("Password reset email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send password reset email to {}: {}", to, e.getMessage());
            throw new RuntimeException("Failed to send email", e);
        }
    }

    @Async
    @Override
    public void sendPasswordChangedEmail(String to, String userName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(appName + " - Password Changed");
            message.setText(buildPasswordChangedEmailBody(userName));
            
            mailSender.send(message);
            log.info("Password changed email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send password changed email to {}: {}", to, e.getMessage());
        }
    }

    @Async
    @Override
    public void sendWelcomeEmail(String to, String userName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject("Welcome to " + appName);
            message.setText(buildWelcomeEmailBody(userName));
            
            mailSender.send(message);
            log.info("Welcome email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send welcome email to {}: {}", to, e.getMessage());
        }
    }

    @Async
    @Override
    public void sendVerificationEmail(String to, String verificationUrl, String userName) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setFrom(fromEmail);
            message.setTo(to);
            message.setSubject(appName + " - Verify Your Email");
            message.setText(buildVerificationEmailBody(userName, verificationUrl));
            
            mailSender.send(message);
            log.info("Verification email sent to: {}", to);
        } catch (Exception e) {
            log.error("Failed to send verification email to {}: {}", to, e.getMessage());
        }
    }

    // Email body builders
    private String buildPasswordResetEmailBody(String userName, String resetUrl) {
        return String.format("""
            Hello %s,
            
            You recently requested to reset your password for your %s account.
            
            Click the link below to reset your password:
            %s
            
            This link will expire in 1 hour.
            
            If you did not request a password reset, please ignore this email or contact support if you have concerns.
            
            Best regards,
            The %s Team
            """, userName, appName, resetUrl, appName);
    }

    private String buildPasswordChangedEmailBody(String userName) {
        return String.format("""
            Hello %s,
            
            Your password for %s has been successfully changed.
            
            If you did not make this change, please contact our support team immediately.
            
            Best regards,
            The %s Team
            """, userName, appName, appName);
    }

    private String buildWelcomeEmailBody(String userName) {
        return String.format("""
            Welcome to %s!
            
            Hello %s,
            
            Thank you for registering! We're excited to have you on board.
            
            You can now start scanning your network infrastructure for security vulnerabilities.
            
            If you have any questions, feel free to reach out to our support team.
            
            Best regards,
            The %s Team
            """, appName, userName, appName);
    }

    private String buildVerificationEmailBody(String userName, String verificationUrl) {
        return String.format("""
            Hello %s,
            
            Please verify your email address by clicking the link below:
            %s
            
            This link will expire in 24 hours.
            
            Best regards,
            The %s Team
            """, userName, verificationUrl, appName);
    }
}