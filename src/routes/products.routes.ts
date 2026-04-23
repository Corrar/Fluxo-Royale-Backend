import { Router } from 'express';
// 1. Importámos também o 'authorizeRole' para proteger a rota de preços
import { authenticate, authorizeRole } from '../middlewares/auth'; 
import { 
    getProducts, 
    getLowStockProducts, 
    createProduct, 
    updateProduct, 
    deleteProduct, 
    updatePurchaseInfo,
    reactivateProduct,
    getInactiveProducts,
    updateProductPrices // 2. Importámos a nova função do financeiro
} from '../controllers/products.controller';

const router = Router();

// Todas estas rotas já terão o prefixo '/products' no server.ts
router.get('/', authenticate, getProducts);
router.get('/low-stock', authenticate, getLowStockProducts);

// 🗑️ Nova rota para buscar produtos inativos (fantasmas)
// É crucial que esta rota venha ANTES das rotas com /:id
router.get('/inactive', authenticate, getInactiveProducts); 

router.post('/', authenticate, createProduct);

// ♻️ Rota para reativar produtos inativos (fantasmas)
router.put('/reactivate/:sku', authenticate, reactivateProduct);

// 💰 NOVA ROTA: Exclusiva para atualizar preços.
// Usamos o 'authenticate' para verificar quem é, e o 'authorizeRole' para garantir que é do setor correto.
router.patch(
    '/:id/prices', 
    authenticate, 
    authorizeRole(['financeiro', 'admin']), // Aqui podes ajustar os cargos que têm permissão
    updateProductPrices
);

// Rotas com parâmetros gerais (devem ficar sempre no final)
router.put('/:id', authenticate, updateProduct);
router.put('/:id/purchase-info', authenticate, updatePurchaseInfo);
router.delete('/:id', authenticate, deleteProduct);

export default router;
