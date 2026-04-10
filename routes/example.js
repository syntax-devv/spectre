const express = require('express');
const router = express.Router();
const prisma = require('../lib/prisma');
const cacheService = require('../services/cacheService');
const { logUtils } = require('../utils');

router.get('/test-connection', async (req, res) => {
  try {
    await prisma.$connect();
    res.json({ 
      message: 'Prisma connection successful!',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logUtils.logDatabaseError('connect', error);
    res.status(500).json({ 
      error: 'Failed to connect to database',
      details: error.message 
    });
  }
});

router.get('/test-redis', async (req, res) => {
  try {
    const testKey = 'test:redis:connection';
    const testValue = { message: 'Redis is working!', timestamp: new Date().toISOString() };
    
    await cacheService.set(testKey, testValue, 60);
    
    const cached = await cacheService.get(testKey);
    
    await cacheService.del(testKey);
    
    res.json({ 
      message: 'Redis connection successful!',
      cached,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    logUtils.logError('Redis connection error', error);
    res.status(500).json({ 
      error: 'Failed to connect to Redis',
      details: error.message 
    });
  }
});

router.get('/users', async (req, res) => {
  try {
    const cacheKey = 'users:all';
    const cachedUsers = await cacheService.get(cacheKey);
    
    if (cachedUsers) {
      res.json({ users: cachedUsers });
    } else {
      const users = await prisma.user.findMany();
      await cacheService.set(cacheKey, users, 60);
      res.json({ users });
    }
  } catch (error) {
    logUtils.logDatabaseError('fetch_users', error);
    res.status(500).json({ 
      error: 'Failed to fetch users',
      details: error.message 
    });
  }
});

router.post('/users', async (req, res) => {
  try {
    const { email, firstName, lastName, password } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    let userData = { email, firstName, lastName };
    
    if (password) {
      const crypto = require('crypto');
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
      userData.passwordHash = `${salt}:${hash}`;
    }
    
    const user = await prisma.user.create({
      data: userData
    });
    
    await cacheService.del('users:all');
    
    res.json({ user });
  } catch (error) {
    logUtils.logDatabaseError('create_user', error);
    res.status(500).json({ 
      error: 'Failed to create user',
      details: error.message 
    });
  }
});

module.exports = router;
