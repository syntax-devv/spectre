const express = require('express');
const router = express.Router();
const prisma = require('../lib/prisma');
const jwtUtils = require('../utils/jwt');
const passwordUtils = require('../utils/password');
const cacheService = require('../services/cacheService');
const { logUtils } = require('../utils');

router.post('/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName } = req.body;
    
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
    
    const passwordValidation = passwordUtils.validatePasswordStrength(password);
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
        avatarUrl: true,
        mfaEnabled: true,
        createdAt: true
      }
    });
    
    const tokens = jwtUtils.generateTokenPair({
      userId: user.id,
      email: user.email
    });
    
    const tokenHash = await passwordUtils.hashToken(tokens.refreshToken);
    
    await prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      }
    });
    
    await cacheService.cacheUser(user.id, user, 300);
    await cacheService.del('users:all');
    
    res.status(201).json({
      message: 'User registered successfully',
      user,
      ...tokens
    });
  } catch (error) {
    logUtils.logAuthError('registration', error, { email: email?.toLowerCase() });
    res.status(500).json({ 
      error: 'Registration failed',
      message: 'An error occurred during registration'
    });
  }
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Email and password are required'
      });
    }
    
    const user = await prisma.user.findUnique({
      where: { email: email.toLowerCase() }
    });
    
    if (!user || !user.passwordHash) {
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password'
      });
    }
    
    const isValidPassword = await passwordUtils.comparePassword(password, user.passwordHash);
    if (!isValidPassword) {
      return res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid email or password'
      });
    }
    
    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });
    
    const tokens = jwtUtils.generateTokenPair({
      userId: user.id,
      email: user.email
    });
    
    const tokenHash = await passwordUtils.hashToken(tokens.refreshToken);
    
    await prisma.refreshToken.create({
      data: {
        userId: user.id,
        tokenHash,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      }
    });
    
    const userResponse = {
      id: user.id,
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      avatarUrl: user.avatarUrl,
      mfaEnabled: user.mfaEnabled,
      lastLoginAt: new Date()
    };
    
    await cacheService.cacheUser(user.id, userResponse, 300);
    
    res.json({
      message: 'Login successful',
      user: userResponse,
      ...tokens
    });
  } catch (error) {
    logUtils.logAuthError('login', error, { email: email?.toLowerCase() });
    res.status(500).json({ 
      error: 'Login failed',
      message: 'An error occurred during login'
    });
  }
});

router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ 
        error: 'Validation failed',
        message: 'Refresh token is required'
      });
    }
    
    const decoded = jwtUtils.verifyRefreshToken(refreshToken);
    
    const allTokens = await prisma.refreshToken.findMany({
      where: { 
        userId: decoded.userId,
        expiresAt: { gt: new Date() },
        revoked: false
      },
      include: { user: true }
    });
    
    let storedToken = null;
    for (const token of allTokens) {
      if (await passwordUtils.compareToken(refreshToken, token.tokenHash)) {
        storedToken = token;
        break;
      }
    }
    
    if (!storedToken || storedToken.expiresAt < new Date()) {
      return res.status(401).json({ 
        error: 'Invalid refresh token',
        message: 'Refresh token is invalid or expired'
      });
    }
    
    await prisma.refreshToken.delete({
      where: { id: storedToken.id }
    });
    
    const tokens = jwtUtils.generateTokenPair({
      userId: decoded.userId,
      email: decoded.email
    });
    
    const tokenHash = await passwordUtils.hashToken(tokens.refreshToken);
    
    await prisma.refreshToken.create({
      data: {
        userId: decoded.userId,
        tokenHash,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      }
    });
    
    res.json({
      message: 'Token refreshed successfully',
      ...tokens
    });
  } catch (error) {
    logUtils.logAuthError('token_refresh', error);
    res.status(500).json({ 
      error: 'Token refresh failed',
      message: 'An error occurred during token refresh'
    });
  }
});

router.post('/logout', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (refreshToken) {
      const allTokens = await prisma.refreshToken.findMany({
        where: { 
          tokenHash: { contains: '' }
        }
      });
      
      for (const token of allTokens) {
        if (await passwordUtils.compareToken(refreshToken, token.tokenHash)) {
          await prisma.refreshToken.delete({
            where: { id: token.id }
          });
          break;
        }
      }
    }
    
    res.json({
      message: 'Logout successful'
    });
  } catch (error) {
    logUtils.logAuthError('logout', error);
    res.status(500).json({ 
      error: 'Logout failed',
      message: 'An error occurred during logout'
    });
  }
});

router.get('/me', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ 
        error: 'Authentication required',
        message: 'Please provide a valid Bearer token'
      });
    }
    
    const token = authHeader.substring(7);
    const decoded = jwtUtils.verifyAccessToken(token);
    
    const cacheKey = cacheService.cacheKey('user', decoded.userId);
    let user = await cacheService.get(cacheKey);
    
    if (!user) {
      user = await prisma.user.findUnique({
        where: { id: decoded.userId },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          avatarUrl: true,
          mfaEnabled: true,
          lastLoginAt: true,
          createdAt: true
        }
      });
      
      if (!user) {
        return res.status(404).json({ 
          error: 'User not found',
          message: 'The user associated with this token no longer exists'
        });
      }
      
      await cacheService.cacheUser(user.id, user, 300);
    }
    
    res.json({
      user
    });
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: 'Token expired',
        message: 'Access token has expired, please refresh'
      });
    }
    
    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({ 
        error: 'Invalid token',
        message: 'The provided token is invalid'
      });
    }
    
    logUtils.logAuthError('get_user', error);
    res.status(500).json({ 
      error: 'Failed to get user',
      message: 'An error occurred while fetching user data'
    });
  }
});

module.exports = router;
