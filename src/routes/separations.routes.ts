import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getSeparations, createSeparation, authorizeSeparation, deleteSeparation } from '../controllers/separations.controller';

const router = Router();
router.use(authenticate);

router.get('/', getSeparations);
router.post('/', createSeparation);
router.put('/:id/authorize', authorizeSeparation);
router.delete('/:id', deleteSeparation);
// Adiciona as rotas de update e returns aqui...

export default router;