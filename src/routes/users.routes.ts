import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getUsers, updateRole, updateStatus, deleteUser, heartbeat } from '../controllers/users.controller';

const router = Router();

// Aplica o middleware de autenticação a TODAS as rotas de utilizadores
router.use(authenticate);

router.get('/', getUsers);
router.put('/:id/heartbeat', heartbeat);
router.put('/:id/role', updateRole);
router.put('/:id/status', updateStatus);
router.delete('/:id', deleteUser);

export default router;