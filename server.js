require('dotenv').config();
const express = require('express');
const prisma = require('./lib/prisma');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

const exampleRoutes = require('./routes/example');

app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Spectre IAM!' });
});
app.use('/api', exampleRoutes);


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
