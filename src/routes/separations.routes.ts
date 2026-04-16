import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { 
    getSeparations, 
    createSeparation, 
    authorizeSeparation, 
    deleteSeparation,
    updateSeparation,      // 👈 Importado
    createReturn,          // 👈 Importado
    updateReturnStatus     // 👈 Importado
} from '../controllers/separations.controller';

const router = Router();

// Aplica o middleware de autenticação a todas as rotas deste ficheiro
router.use(authenticate);

// 📋 Rotas de Listagem e Criação Base
router.get('/', getSeparations);
router.post('/', createSeparation);

// ♻️ Rotas de Devoluções
// ATENÇÃO: Tem de ficar antes das rotas com /:id para o Express não confundir 'returns' com um ID
router.put('/returns/:returnId', updateReturnStatus);
router.post('/:id/return', createReturn);

// 📦 Rotas de Gestão do Pedido (com parâmetro :id)
router.put('/:id/authorize', authorizeSeparation);
router.put('/:id', updateSeparation); // 👈 Esta é a rota que estava a faltar e dava 404!
router.delete('/:id', deleteSeparation);

export default router;
