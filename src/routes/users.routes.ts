import { Router } from 'express';
import { authenticate, authorizeRole } from '../middlewares/auth';
// 1. Importa a função resetPassword (que vamos criar no controlador)
import { getUsers, updateRole, updateStatus, deleteUser, heartbeat, resetPassword } from '../controllers/users.controller';

const router = Router();

// Aplica o middleware de autenticação a TODAS as rotas de utilizadores
router.use(authenticate);

router.get('/', getUsers);
router.put('/:id/heartbeat', heartbeat);

// 🔒 Ações administrativas: exigem cargo admin (antes qualquer autenticado
// podia autopromover-se ou apagar contas).
router.put('/:id/role', authorizeRole(['admin']), updateRole);
router.put('/:id/status', authorizeRole(['admin']), updateStatus);
router.delete('/:id', authorizeRole(['admin']), deleteUser);

// 2. Adiciona a nova rota POST para redefinir a senha
router.post('/:id/reset-password', authorizeRole(['admin']), resetPassword);

export default router;
