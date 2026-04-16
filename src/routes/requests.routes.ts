import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getRequests, getMyRequests, createRequest, updateRequestStatus, deleteRequest } from '../controllers/requests.controller';

const router = Router();

router.use(authenticate); // Aplica a todas as rotas

router.get('/', getRequests);
router.get('/my', getMyRequests); // Substitui a antiga rota solta /my-requests
router.post('/', createRequest);
router.put('/:id/status', updateRequestStatus);
router.delete('/:id', deleteRequest);

export default router;