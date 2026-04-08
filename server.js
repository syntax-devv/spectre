require('dotenv').config();
const express = require('express');
const prisma = require('./lib/prisma');
const redisClient = require('./lib/redis');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const exampleRoutes = require('./routes/example');

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Spectre IAM!' });
});
app.use('/api', exampleRoutes);

async function startServer() {
  try {
    await redisClient.connect();
    
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Redis status: ${redisClient.isReady() ? 'Connected' : 'Disconnected'}`);
    });
  } catch (error) {
    console.error('Failed to start server:', error);
  }
}

startServer();
