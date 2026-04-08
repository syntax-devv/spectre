const redisClient = require('../lib/redis');

class CacheService {
  constructor() {
    this.defaultTTL = 3600;
  }

  async get(key) {
    try {
      if (!redisClient.isReady()) {
        return null;
      }
      
      const value = await redisClient.getClient().get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      console.error('Cache get error:', error);
      return null;
    }
  }

  async set(key, value, ttl = this.defaultTTL) {
    try {
      if (!redisClient.isReady()) {
        return false;
      }
      
      await redisClient.getClient().setEx(key, ttl, JSON.stringify(value));
      return true;
    } catch (error) {
      console.error('Cache set error:', error);
      return false;
    }
  }

  async del(key) {
    try {
      if (!redisClient.isReady()) {
        return false;
      }
      
      await redisClient.getClient().del(key);
      return true;
    } catch (error) {
      console.error('Cache delete error:', error);
      return false;
    }
  }

  async delPattern(pattern) {
    try {
      if (!redisClient.isReady()) {
        return false;
      }
      
      const keys = await redisClient.getClient().keys(pattern);
      if (keys.length > 0) {
        await redisClient.getClient().del(keys);
      }
      return true;
    } catch (error) {
      console.error('Cache delete pattern error:', error);
      return false;
    }
  }

  async exists(key) {
    try {
      if (!redisClient.isReady()) {
        return false;
      }
      
      const result = await redisClient.getClient().exists(key);
      return result === 1;
    } catch (error) {
      console.error('Cache exists error:', error);
      return false;
    }
  }

  cacheKey(type, identifier, orgId = null) {
    const parts = ['spectre', type, identifier];
    if (orgId) parts.push(orgId);
    return parts.join(':');
  }

  async cacheUser(userId, userData, ttl = this.defaultTTL) {
    const key = this.cacheKey('user', userId);
    return await this.set(key, userData, ttl);
  }

  async getUser(userId) {
    const key = this.cacheKey('user', userId);
    return await this.get(key);
  }

  async invalidateUser(userId) {
    const key = this.cacheKey('user', userId);
    return await this.del(key);
  }

  async cacheOrganization(orgId, orgData, ttl = this.defaultTTL) {
    const key = this.cacheKey('org', orgId);
    return await this.set(key, orgData, ttl);
  }

  async getOrganization(orgId) {
    const key = this.cacheKey('org', orgId);
    return await this.get(key);
  }

  async invalidateOrganization(orgId) {
    const patterns = [
      this.cacheKey('org', orgId),
      this.cacheKey('user', '*', orgId),
      this.cacheKey('membership', '*', orgId),
      this.cacheKey('role', '*', orgId)
    ];
    
    for (const pattern of patterns) {
      await this.delPattern(pattern);
    }
  }

  async cacheUserMemberships(userId, memberships, ttl = this.defaultTTL) {
    const key = this.cacheKey('memberships', userId);
    return await this.set(key, memberships, ttl);
  }

  async getUserMemberships(userId) {
    const key = this.cacheKey('memberships', userId);
    return await this.get(key);
  }

  async invalidateUserMemberships(userId) {
    const key = this.cacheKey('memberships', userId);
    return await this.del(key);
  }
}

module.exports = new CacheService();
