import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { 
    getProducts, 
    getLowStockProducts, 
    createProduct, 
    updateProduct, 
    deleteProduct, 
    updatePurchaseInfo,
    reactivateProduct,
    getInactiveProducts // 👈 1. Importámos a nossa nova função aqui
} from '../controllers/products.controller';

const router = Router();

// Todas estas rotas já terão o prefixo '/products' no server.ts
router.get('/', authenticate, getProducts);
router.get('/low-stock', authenticate, getLowStockProducts);

// 🗑️ 2. Nova rota para buscar produtos inativos (fantasmas)
// É crucial que esta rota venha ANTES das rotas com /:id
router.get('/inactive', authenticate, getInactiveProducts); 

router.post('/', authenticate, createProduct);

// ♻️ Rota para reativar produtos inativos (fantasmas)
router.put('/reactivate/:sku', authenticate, reactivateProduct);

// Rotas com parâmetros (devem ficar no final)
router.put('/:id', authenticate, updateProduct);
router.put('/:id/purchase-info', authenticate, updatePurchaseInfo);
router.delete('/:id', authenticate, deleteProduct);

export default router;
