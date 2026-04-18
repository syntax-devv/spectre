const { logUtils } = require('../utils');

class CacheService {
  constructor() {
    this.store = new Map();
    this.setStore = new Map();
    this.prefix = 'spectre:';
    this.redisClient = null;
    this.redisReady = false;
    this.redisInitPromise = null;
  }

  async init() {
    if (this.redisInitPromise) {
      return this.redisInitPromise;
    }

    this.redisInitPromise = this._initRedis();
    return this.redisInitPromise;
  }

  async _initRedis() {
    if (!process.env.REDIS_URL) {
      return;
    }

    try {
      const { createClient } = require('redis');
      this.redisClient = createClient({
        url: process.env.REDIS_URL
      });

      this.redisClient.on('error', (error) => {
        this.redisReady = false;
        logUtils.logError(error, { action: 'redis_client_error' });
      });

      await this.redisClient.connect();
      this.redisReady = true;
      logUtils.logCache('connect', 'redis');
    } catch (error) {
      this.redisClient = null;
      this.redisReady = false;
      logUtils.logError(error, { action: 'redis_init_failed_fallback_memory' });
    }
  }

  async isRedisEnabled() {
    await this.init();
    return this.redisReady && this.redisClient;
  }

  cacheKey(...parts) {
    return `${this.prefix}${parts.join(':')}`;
  }

  _isExpired(entry) {
    return entry.expiresAt !== null && entry.expiresAt <= Date.now();
  }

  async set(key, value, ttlMs = null) {
    if (await this.isRedisEnabled()) {
      const payload = JSON.stringify(value);
      if (ttlMs) {
        await this.redisClient.set(key, payload, { PX: ttlMs });
      } else {
        await this.redisClient.set(key, payload);
      }
      logUtils.logCache('set', key);
      return true;
    }

    const expiresAt = ttlMs ? Date.now() + ttlMs : null;
    this.store.set(key, { value, expiresAt });
    logUtils.logCache('set', key);
    return true;
  }

  async get(key) {
    if (await this.isRedisEnabled()) {
      const value = await this.redisClient.get(key);
      const hit = value !== null;
      logUtils.logCache('get', key, hit);
      return value ? JSON.parse(value) : null;
    }

    const entry = this.store.get(key);
    if (!entry) {
      logUtils.logCache('get', key, false);
      return null;
    }

    if (this._isExpired(entry)) {
      this.store.delete(key);
      logUtils.logCache('get', key, false);
      return null;
    }

    logUtils.logCache('get', key, true);
    return entry.value;
  }

  async del(key) {
    if (await this.isRedisEnabled()) {
      await this.redisClient.del(key);
      logUtils.logCache('del', key);
      return true;
    }

    this.store.delete(key);
    logUtils.logCache('del', key);
    return true;
  }

  async expire(key, ttlMs) {
    if (await this.isRedisEnabled()) {
      const result = await this.redisClient.pExpire(key, ttlMs);
      return result === 1;
    }

    const entry = this.store.get(key);
    if (!entry) {
      return false;
    }

    entry.expiresAt = Date.now() + ttlMs;
    this.store.set(key, entry);
    return true;
  }

  async sadd(key, value) {
    if (await this.isRedisEnabled()) {
      return this.redisClient.sAdd(key, value);
    }

    const set = this.setStore.get(key) || new Set();
    set.add(value);
    this.setStore.set(key, set);
    return set.size;
  }

  async srem(key, value) {
    if (await this.isRedisEnabled()) {
      return this.redisClient.sRem(key, value);
    }

    const set = this.setStore.get(key);
    if (!set) {
      return 0;
    }
    const didDelete = set.delete(value);
    if (set.size === 0) {
      this.setStore.delete(key);
    } else {
      this.setStore.set(key, set);
    }
    return didDelete ? 1 : 0;
  }

  async smembers(key) {
    if (await this.isRedisEnabled()) {
      return this.redisClient.sMembers(key);
    }

    const set = this.setStore.get(key);
    if (!set) {
      return [];
    }
    return Array.from(set);
  }

  async cacheUser(userId, user, ttlMs = 300000) {
    const key = this.cacheKey('user', userId);
    return this.set(key, user, ttlMs);
  }
}

module.exports = new CacheService();
