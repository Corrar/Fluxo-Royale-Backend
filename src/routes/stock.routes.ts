import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getStock, getStockReservations, updateStock, manualEntry, manualWithdrawal } from '../controllers/stock.controller';

const router = Router();

router.use(authenticate);

// Rotas nativas do stock
router.get('/', getStock);
router.get('/:id/reservations', getStockReservations);
router.put('/:id', updateStock);

// Rotas de transações manuais (agrupámo-las aqui pela sua relação íntima com o stock físico)
router.post('/manual-entry', manualEntry);
router.post('/manual-withdrawal', manualWithdrawal);

export default router;