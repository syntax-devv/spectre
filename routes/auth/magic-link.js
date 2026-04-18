const express = require('express');
const router = express.Router();
const prisma = require('../../lib/prisma');
const jwtUtils = require('../../utils/jwt');
const passwordUtils = require('../../utils/password');
const emailService = require('../../services/emailService');
const { logUtils } = require('../../utils');

const persistRefreshToken = async (refreshToken, userId, req) => {
  const tokenHash = await passwordUtils.hashToken(refreshToken);
  const decoded = jwtUtils.decodeToken(refreshToken);
  const expiresAt = decoded?.exp
    ? new Date(decoded.exp * 1000)
    : new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

  await prisma.refreshToken.create({
    data: {
      tokenHash,
      userId,
      userAgent: req.get('User-Agent') || null,
      ipAddress: req.ip,
      expiresAt
    }
  });
};

router.post('/magic-link', async (req, res) => {
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
        message: 'If an account exists with this email, a magic link has been sent'
      });
    }

    const token = require('crypto').randomBytes(32).toString('hex');
    const tokenHash = await passwordUtils.hashToken(token);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1000);

    await prisma.magicLinkToken.create({
      data: {
        token: tokenHash,
        tokenHash,
        userId: user.id,
        email: email.toLowerCase(),
        expiresAt
      }
    });

    await emailService.sendMagicLink(email, token);

    logUtils.logAuth('magic_link_sent', user.id, { 
      email: email.toLowerCase(),
      ipAddress: req.ip
    });

    res.json({ 
      message: 'If an account exists with this email, a magic link has been sent'
    });
  } catch (error) {
    logUtils.logAuthError('magic_link_send', error, { email });
    res.status(500).json({ 
      error: 'Failed to send magic link',
      message: 'An error occurred while sending the magic link'
    });
  }
});

router.post('/magic-link/verify', async (req, res) => {
  const { token, email } = req.body;
  
  try {
    if (!token || !email) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Token and email are required'
      });
    }

    const tokenHash = await passwordUtils.hashToken(token);
    
    const magicLinkToken = await prisma.magicLinkToken.findFirst({
      where: {
        tokenHash,
        email: email.toLowerCase(),
        expiresAt: { gt: new Date() }
      },
      include: {
        user: {
          select: {
            id: true,
            email: true,
            firstName: true,
            lastName: true,
            avatarUrl: true,
            mfaEnabled: true
          }
        }
      }
    });

    if (!magicLinkToken) {
      return res.status(401).json({ 
        error: 'Invalid or expired magic link',
        message: 'The magic link is invalid or has expired'
      });
    }

    await prisma.magicLinkToken.delete({
      where: { id: magicLinkToken.id }
    });

    await prisma.user.update({
      where: { id: magicLinkToken.user.id },
      data: { lastLoginAt: new Date() }
    });

    const tokens = jwtUtils.generateTokenPair({ userId: magicLinkToken.user.id });
    await persistRefreshToken(tokens.refreshToken, magicLinkToken.user.id, req);

    const userResponse = {
      id: magicLinkToken.user.id,
      email: magicLinkToken.user.email,
      firstName: magicLinkToken.user.firstName,
      lastName: magicLinkToken.user.lastName,
      avatarUrl: magicLinkToken.user.avatarUrl,
      mfaEnabled: magicLinkToken.user.mfaEnabled,
      lastLoginAt: new Date()
    };

    logUtils.logAuth('magic_link_success', magicLinkToken.user.id, {
      email: magicLinkToken.email,
      ipAddress: req.ip
    });

    res.json({
      message: 'Sign-in successful',
      user: userResponse,
      ...tokens
    });
  } catch (error) {
    logUtils.logAuthError('magic_link_verify', error);
    res.status(500).json({ 
      error: 'Failed to verify magic link',
      message: 'An error occurred while verifying sign-in link'
    });
  }
});

module.exports = router;
