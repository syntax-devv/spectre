require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const { sessionMiddleware } = require('./middleware/session');
const app = express();
const PORT = process.env.PORT || 3000;

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
    app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`);
      console.log('Session service: In-memory mode');
    });
  } catch (error) {
    console.error('Failed to start server:', error);
  }
}

startServer();
