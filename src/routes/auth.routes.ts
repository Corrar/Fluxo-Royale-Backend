import { Router } from 'express';
import { login, logout, register } from '../controllers/auth.controller';
import { authLimiter } from '../middlewares/rateLimiters';
import { authenticate, authorizeRole } from '../middlewares/auth';

const router = Router();

router.post('/login', authLimiter, login);
router.post('/logout', authenticate, logout);

// 🔒 Criação de usuários é exclusiva de administradores. Antes esta rota era
// pública e o cargo vinha do body — qualquer pessoa criava uma conta 'admin'.
router.post('/register', authenticate, authorizeRole(['admin']), register);

export default router;
