import express from 'express';
const router = express.Router();
import UserController from '../controllers/userController.js';

// Public Routes
router.post('/register', UserController.userRegistration);

export default router;
