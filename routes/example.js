const express = require('express');
const router = express.Router();
const prisma = require('../lib/prisma');

router.get('/test-connection', async (req, res) => {
  try {
    await prisma.$connect();
    res.json({ 
      message: 'Prisma connection successful!',
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Prisma connection error:', error);
    res.status(500).json({ 
      error: 'Failed to connect to database',
      details: error.message 
    });
  }
});

router.get('/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany();
    res.json({ users });
  } catch (error) {
    console.error('Error fetching users:', error);
    res.status(500).json({ 
      error: 'Failed to fetch users',
      details: error.message 
    });
  }
});

router.post('/users', async (req, res) => {
  try {
    const { email, name } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }
    
    const user = await prisma.user.create({
      data: { email, name }
    });
    
    res.json({ user });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ 
      error: 'Failed to create user',
      details: error.message 
    });
  }
});

module.exports = router;
