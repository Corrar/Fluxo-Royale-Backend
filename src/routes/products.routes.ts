import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { 
    getProducts, 
    getLowStockProducts, 
    createProduct, 
    updateProduct, 
    deleteProduct, 
    updatePurchaseInfo 
} from '../controllers/products.controller';

const router = Router();

// Todas estas rotas já terão o prefixo '/products' no server.ts
router.get('/', authenticate, getProducts);
router.get('/low-stock', authenticate, getLowStockProducts);
router.post('/', authenticate, createProduct);
router.put('/:id', authenticate, updateProduct);
router.put('/:id/purchase-info', authenticate, updatePurchaseInfo);
router.delete('/:id', authenticate, deleteProduct);

export default router;