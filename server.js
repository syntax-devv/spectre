require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { sessionMiddleware } = require('./middleware/session');
const cacheService = require('./services/cacheService');
const app = express();
const PORT = process.env.PORT || 3000;
let serverInstance = null;

app.use(cookieParser());
app.use(express.json());
app.use(sessionMiddleware());

const exampleRoutes = require('./routes/example');
const authRoutes = require('./routes/auth');

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Spectre IAM!' });
});
app.use('/api/auth', authRoutes);
// app.use('/api', exampleRoutes);

async function startServer() {
  try {
    await cacheService.init();
    serverInstance = app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log(`Session service: ${process.env.REDIS_URL ? 'Redis/In-memory fallback mode' : 'In-memory mode'}`);
    });
    return serverInstance;
  } catch (error) {
    console.error('Failed to start server:', error);
    throw error;
  }
}

async function stopServer() {
  if (!serverInstance) {
    return;
  }

  await new Promise((resolve, reject) => {
    serverInstance.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
  serverInstance = null;
}

if (require.main === module) {
  startServer();
}

module.exports = {
  app,
  startServer,
  stopServer
};
