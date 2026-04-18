const express = require('express');
const router = express.Router();
const prisma = require('../../lib/prisma');
const passwordUtils = require('../../utils/password');
const emailService = require('../../services/emailService');
const { logUtils } = require('../../utils');

router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  try {
    if (!email) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Email is required'
      });
    }

    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });

    if (!user) {
      return res.json({ 
        message: 'If an account exists with this email, a password reset link has been sent'
      });
    }
    const token = require('crypto').randomBytes(32).toString('hex');
    const tokenHash = await passwordUtils.hashToken(token);
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000);
    
    await prisma.passwordResetToken.create({
      data: {
        token: tokenHash,
        tokenHash,
        userId: user.id,
        email: email.toLowerCase(),
        expiresAt
      }
    });

    await emailService.sendPasswordReset(email, token);

    logUtils.logAuth('password_reset_sent', user.id, { 
      email: email.toLowerCase(),
      ipAddress: req.ip
    });

    res.json({ 
      message: 'If an account exists with this email, a password reset link has been sent'
    });
  } catch (error) {
    logUtils.logAuthError('password_reset_send', error, { email });
    res.status(500).json({ 
      error: 'Failed to send password reset',
      message: 'An error occurred while sending the password reset email'
    });
  }
});

router.post('/reset-password', async (req, res) => {
  const { token, email, newPassword } = req.body;
  
  try {
    if (!token || !email || !newPassword) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Token, email, and new password are required'
      });
    }

    const passwordValidation = passwordUtils.validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Weak password',
        message: passwordValidation.errors.join(', ')
      });
    }

    const tokenHash = await passwordUtils.hashToken(token);
    
    const resetToken = await prisma.passwordResetToken.findFirst({
      where: {
        tokenHash,
        email: email.toLowerCase(),
        expiresAt: { gt: new Date() }
      },
      include: {
        user: true
      }
    });

    if (!resetToken) {
      return res.status(401).json({ 
        error: 'Invalid or expired reset token',
        message: 'The password reset link is invalid or has expired'
      });
    }

    const hashedPassword = await passwordUtils.hashPassword(newPassword);

    await prisma.user.update({
      where: { id: resetToken.userId },
      data: { 
        passwordHash: hashedPassword,
        updatedAt: new Date()
      }
    });

    await prisma.passwordResetToken.delete({
      where: { id: resetToken.id }
    });
    
    await prisma.refreshToken.deleteMany({
      where: { userId: resetToken.userId }
    });

    logUtils.logAuth('password_reset_success', resetToken.userId, {
      email: email.toLowerCase(),
      ipAddress: req.ip
    });

    res.json({
      message: 'Password reset successful',
      email: email.toLowerCase()
    });
  } catch (error) {
    logUtils.logAuthError('password_reset', error);
    res.status(500).json({ 
      error: 'Failed to reset password',
      message: 'An error occurred while resetting the password'
    });
  }
});

module.exports = router;
