import { Router } from 'express';
import { login, logout, register } from '../controllers/auth.controller';
import { authLimiter } from '../middlewares/rateLimiters';
import { authenticate } from '../middlewares/auth';

const router = Router();

router.post('/login', authLimiter, login);
router.post('/logout', authenticate, logout);
router.post('/register', register); // Em alguns sistemas o register também exige autenticação, se for o caso avisar-me

export default router;
