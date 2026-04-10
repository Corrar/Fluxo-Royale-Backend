import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getTravelOrders, createTravelOrder, reconcileTravelOrder, updateTravelOrder, deleteTravelOrder } from '../controllers/travels.controller';

const router = Router();
router.use(authenticate);

router.get('/', getTravelOrders);
router.post('/', createTravelOrder);
router.post('/:id/reconcile', reconcileTravelOrder);
router.put('/:id', updateTravelOrder);
router.delete('/:id', deleteTravelOrder);

export default router;
