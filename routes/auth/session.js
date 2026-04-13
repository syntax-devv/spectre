const express = require('express');
const router = express.Router();
const prisma = require('../../lib/prisma');
const { passwordUtils } = require('../../utils/password');
const { sessionService, createSessionCookie, destroySessionCookie } = require('../../middleware/session');
const { logUtils } = require('../../utils');


router.post('/session-login', async (req, res) => {
  try {
    const { email, password, rememberMe = false } = req.body;
    
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

    const ttl = rememberMe ? 7 * 24 * 60 * 60 * 1000 : 30 * 60 * 1000;
    const { sessionId, session } = await sessionService.createSession(user.id, {
      email: user.email,
      firstName: user.firstName,
      lastName: user.lastName,
      avatarUrl: user.avatarUrl,
      mfaEnabled: user.mfaEnabled
    }, ttl);

    createSessionCookie(res, sessionId, rememberMe);

    await prisma.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
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

    logUtils.logAuth('session_login_success', user.id, { 
      email: user.email,
      sessionId,
      rememberMe 
    });

    res.json({
      message: 'Login successful',
      user: userResponse,
      session: {
        id: sessionId,
        expiresAt: session.expiresAt
      }
    });
  } catch (error) {
    logUtils.logAuthError('session_login', error);
    res.status(500).json({ 
      error: 'Login failed',
      message: 'An error occurred during login'
    });
  }
});

router.post('/session-logout', async (req, res) => {
  try {
    const sessionId = req.cookies['spectre-session'];
    
    if (sessionId) {
      await sessionService.destroySession(sessionId);
    }

    destroySessionCookie(res);

    logUtils.logAuth('session_logout', null, { sessionId });

    res.json({
      message: 'Logout successful'
    });
  } catch (error) {
    logUtils.logAuthError('session_logout', error);
    res.status(500).json({ 
      error: 'Logout failed',
      message: 'An error occurred during logout'
    });
  }
});

router.get('/session-info', async (req, res) => {
  try {
    const sessionId = req.cookies['spectre-session'];
    
    if (!sessionId) {
      return res.status(401).json({ 
        error: 'Not authenticated',
        message: 'No active session found'
      });
    }

    const session = await sessionService.getSession(sessionId);
    
    if (!session) {
      destroySessionCookie(res);
      return res.status(401).json({ 
        error: 'Session expired',
        message: 'Your session has expired'
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.userId },
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
      await sessionService.destroySession(sessionId);
      destroySessionCookie(res);
      return res.status(401).json({ 
        error: 'User not found',
        message: 'User associated with session no longer exists'
      });
    }

    logUtils.logAuth('session_info_accessed', user.id, { sessionId });

    res.json({
      user,
      session: {
        id: sessionId,
        createdAt: session.createdAt,
        lastActivity: session.lastActivity,
        expiresAt: session.expiresAt
      }
    });
  } catch (error) {
    logUtils.logAuthError('session_info', error);
    res.status(500).json({ 
      error: 'Failed to get session info',
      message: 'An error occurred while fetching session information'
    });
  }
});

router.post('/destroy-all-sessions', async (req, res) => {
  try {
    const sessionId = req.cookies['spectre-session'];
    
    if (!sessionId) {
      return res.status(401).json({ 
        error: 'Not authenticated',
        message: 'No active session found'
      });
    }

    const session = await sessionService.getSession(sessionId);
    
    if (!session) {
      return res.status(401).json({ 
        error: 'Session expired',
        message: 'Your session has expired'
      });
    }

    const destroyedCount = await sessionService.destroyAllUserSessions(
      session.userId, 
      sessionId
    );

    logUtils.logAuth('all_sessions_destroyed', session.userId, { 
      destroyedCount,
      currentSessionId: sessionId 
    });

    res.json({
      message: `Destroyed ${destroyedCount} other sessions successfully`,
      destroyedCount
    });
  } catch (error) {
    logUtils.logAuthError('destroy_all_sessions', error);
    res.status(500).json({ 
      error: 'Failed to destroy sessions',
      message: 'An error occurred while destroying other sessions'
    });
  }
});

module.exports = router;
