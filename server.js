const express = require('express');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());


app.get('/', (req, res) => {
  res.json({ message: 'Welcome to Express API!' });
});


app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
