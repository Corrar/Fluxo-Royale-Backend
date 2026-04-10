import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getPermissions, updatePermissions } from '../controllers/permissions.controller';

const router = Router();

// Aplica a autenticação a todas as rotas de permissões
router.use(authenticate);

router.get('/', getPermissions);
router.post('/', updatePermissions);

export default router;
