import dotenv from 'dotenv';
dotenv.config();
import express from 'express';
import cors from 'cors';
import connectDB from './config/connectdb.js';
import userRoutes from './routes/userRoutes.js';
const app = express();
app.use(express.urlencoded({ extended: true }));
const port = process.env.PORT;
const DATABASE_URL = process.env.DATABASE_URL;

// CORS Policy
app.use(cors());

// JSON
app.use(express.json());

// Database Connection
connectDB(DATABASE_URL);

app.use('/api/user', userRoutes);

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
