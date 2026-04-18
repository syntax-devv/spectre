const cacheService = require('./cacheService');
const { logUtils } = require('../utils');

class SessionService {
  constructor() {
    this.sessionPrefix = 'session:';
    this.userSessionsPrefix = 'user_sessions:';
    this.defaultTTL = 30 * 60 * 1000;
  }

  generateSessionId() {
    const crypto = require('crypto');
    return crypto.randomBytes(32).toString('hex');
  }

  async createSession(userId, sessionData = {}, ttl = this.defaultTTL) {
    try {
      const ttlMs = typeof ttl === 'number' && ttl > 0 ? ttl : this.defaultTTL;
      const sessionId = this.generateSessionId();
      const sessionKey = this.sessionPrefix + sessionId;
      const userSessionsKey = this.userSessionsPrefix + userId;

      const session = {
        id: sessionId,
        userId,
        ...sessionData,
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString(),
        ttlMs,
        expiresAt: new Date(Date.now() + ttlMs).toISOString()
      };

      await cacheService.set(sessionKey, session, ttlMs);

      await cacheService.sadd(userSessionsKey, sessionId);
      await cacheService.expire(userSessionsKey, ttlMs);

      logUtils.logAuth('session_created', userId, { sessionId });
      
      return {
        sessionId,
        session
      };
    } catch (error) {
      logUtils.logAuthError('session_create', error, { userId });
      throw error;
    }
  }

  async getSession(sessionId) {
    try {
      const sessionKey = this.sessionPrefix + sessionId;
      const session = await cacheService.get(sessionKey);

      if (session) {
        const ttlMs = session.ttlMs || this.defaultTTL;
        session.lastActivity = new Date().toISOString();
        session.expiresAt = new Date(Date.now() + ttlMs).toISOString();
        await cacheService.set(sessionKey, session, ttlMs);
        
        logUtils.logAuth('session_accessed', session.userId, { sessionId });
        return session;
      }

      return null;
    } catch (error) {
      logUtils.logAuthError('session_get', error, { sessionId });
      return null;
    }
  }

  async updateSession(sessionId, updateData) {
    try {
      const session = await this.getSession(sessionId);
      
      if (!session) {
        return null;
      }

      const sessionKey = this.sessionPrefix + sessionId;
      const updatedSession = {
        ...session,
        ...updateData,
        lastActivity: new Date().toISOString()
      };

      const ttlMs = updatedSession.ttlMs || this.defaultTTL;
      updatedSession.expiresAt = new Date(Date.now() + ttlMs).toISOString();
      await cacheService.set(sessionKey, updatedSession, ttlMs);
      
      logUtils.logAuth('session_updated', session.userId, { sessionId });
      
      return updatedSession;
    } catch (error) {
      logUtils.logAuthError('session_update', error, { sessionId });
      throw error;
    }
  }

  async destroySession(sessionId) {
    try {
      const session = await this.getSession(sessionId);
      
      if (!session) {
        return false;
      }

      const sessionKey = this.sessionPrefix + sessionId;
      const userSessionsKey = this.userSessionsPrefix + session.userId;

      await cacheService.del(sessionKey);

      await cacheService.srem(userSessionsKey, sessionId);

      logUtils.logAuth('session_destroyed', session.userId, { sessionId });
      
      return true;
    } catch (error) {
      logUtils.logAuthError('session_destroy', error, { sessionId });
      return false;
    }
  }

  async destroyAllUserSessions(userId, excludeSessionId = null) {
    try {
      const userSessionsKey = this.userSessionsPrefix + userId;
      const sessionIds = await cacheService.smembers(userSessionsKey);

      if (!sessionIds || sessionIds.length === 0) {
        return 0;
      }

      let destroyedCount = 0;

      for (const sessionId of sessionIds) {
        if (sessionId === excludeSessionId) {
          continue;
        }

        await this.destroySession(sessionId);
        destroyedCount++;
      }

      logUtils.logAuth('all_user_sessions_destroyed', userId, { 
        destroyedCount,
        excludeSessionId
      });

      return destroyedCount;
    } catch (error) {
      logUtils.logAuthError('destroy_all_sessions', error, { userId });
      return 0;
    }
  }

  async getUserSessions(userId) {
    try {
      const userSessionsKey = this.userSessionsPrefix + userId;
      const sessionIds = await cacheService.smembers(userSessionsKey);

      if (!sessionIds || sessionIds.length === 0) {
        return [];
      }

      const sessions = [];
      
      for (const sessionId of sessionIds) {
        const session = await this.getSession(sessionId);
        if (session) {
          sessions.push(session);
        }
      }

      return sessions;
    } catch (error) {
      logUtils.logAuthError('get_user_sessions', error, { userId });
      return [];
    }
  }

  async cleanupExpiredSessions() {
    try {
      logUtils.logAuth('session_cleanup_started', null, {});
      
      return true;
    } catch (error) {
      logUtils.logAuthError('session_cleanup', error);
      return false;
    }
  }

  async validateSession(sessionId) {
    const session = await this.getSession(sessionId);
    
    if (!session) {
      return { valid: false, reason: 'Session not found' };
    }

    return { 
      valid: true, 
      session 
    };
  }
}

module.exports = new SessionService();
