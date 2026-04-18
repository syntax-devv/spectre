const express = require('express');
const router = express.Router();
const prisma = require('../../lib/prisma');
const jwtUtils = require('../../utils/jwt');
const passwordUtils = require('../../utils/password');
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

router.post('/register', async (req, res) => {
  const { email, password, firstName, lastName } = req.body;
  
  try {
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Email and password are required'
      });
    }
    
    const existingUser = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });
    
    if (existingUser) {
      return res.status(409).json({ 
        error: 'User exists',
        message: 'A user with this email already exists'
      });
    }
    
    const passwordValidation = passwordUtils.validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: 'Weak password',
        message: passwordValidation.errors.join(', ')
      });
    }
    
    const hashedPassword = await passwordUtils.hashPassword(password);
    
    const user = await prisma.user.create({
      data: {
        email: email.toLowerCase(),
        passwordHash: hashedPassword,
        firstName,
        lastName
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        createdAt: true
      }
    });

    logUtils.logAuth('user_registered', user.id, { email: user.email });
    
    res.status(201).json({
      message: 'User registered successfully',
      user
    });
  } catch (error) {
    logUtils.logAuthError('registration', error, { email });
    res.status(500).json({ 
      error: 'Registration failed',
      message: 'An error occurred during registration'
    });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Email and password are required'
      });
    }

    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });

    if (!user || !(await passwordUtils.comparePassword(password, user.passwordHash))) {
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password'
      });
    }

    // Update last login
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });

    const tokens = jwtUtils.generateTokenPair({ userId: user.id });
    await persistRefreshToken(tokens.refreshToken, user.id, req);

    const userResponse = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      avatarUrl: user.avatarUrl,
      mfaEnabled: user.mfaEnabled,
      lastLoginAt: new Date()
    };

    logUtils.logAuth('jwt_login_success', user.id, { email: user.email });

    res.json({
      message: 'Login successful',
      user: userResponse,
      ...tokens
    });
  } catch (error) {
    logUtils.logAuthError('jwt_login', error, { email });
    res.status(500).json({ 
      error: 'Login failed',
      message: 'An error occurred during login'
    });
  }
});

router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;
  
  try {
    if (!refreshToken) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Refresh token is required'
      });
    }

    const decoded = jwtUtils.verifyRefreshToken(refreshToken);
    const userId = typeof decoded === 'string' ? decoded : decoded.userId;
    if (!userId) {
      return res.status(401).json({
        error: 'Invalid token',
        message: 'Refresh token payload is invalid'
      });
    }
    
    const storedToken = await prisma.refreshToken.findUnique({
      where: { tokenHash: await passwordUtils.hashToken(refreshToken) }
    });

    if (!storedToken || storedToken.userId !== userId) {
      return res.status(401).json({ 
        error: 'Invalid token',
        message: 'Refresh token is invalid or expired'
      });
    }

    const newTokens = jwtUtils.generateTokenPair({ userId });

    // Remove old refresh token
    await prisma.refreshToken.delete({
      where: { id: storedToken.id }
    });
    await persistRefreshToken(newTokens.refreshToken, userId, req);

    logUtils.logAuth('token_refreshed', userId);

    res.json({
      message: 'Token refreshed successfully',
      ...newTokens
    });
  } catch (error) {
    logUtils.logAuthError('token_refresh', error);
    res.status(401).json({ 
      error: 'Token refresh failed',
      message: 'Invalid or expired refresh token'
    });
  }
});

router.post('/logout', async (req, res) => {
  const { refreshToken } = req.body;
  
  try {
    if (refreshToken) {
      const tokenHash = await passwordUtils.hashToken(refreshToken);
      await prisma.refreshToken.deleteMany({
        where: { tokenHash }
      });
    }

    logUtils.logAuth('jwt_logout', null, { hasRefreshToken: !!refreshToken });
    
    res.json({
      message: 'Logout successful'
    });
  } catch (error) {
    logUtils.logAuthError('jwt_logout', error);
    res.status(500).json({ 
      error: 'Logout failed',
      message: 'An error occurred during logout'
    });
  }
});

module.exports = router;
