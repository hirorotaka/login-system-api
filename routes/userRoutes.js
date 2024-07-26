import express from 'express';
const router = express.Router();
import UserController from '../controllers/userController.js';
import checkUserAuth from '../middlewares/auth-middleware.js';

// Public Routes
router.post('/register', UserController.userRegistration);
router.post('/login', UserController.userLogin);

// Protected Routes
router.post(
  '/changepassword',
  checkUserAuth,
  UserController.changeUserPassword
);

export default router;
