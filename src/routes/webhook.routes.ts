import { Router } from 'express';
// Importamos a função principal que criámos no controlador
import { handleDriveWebhook } from '../controllers/webhook.controller';

const router = Router();

/**
 * ROTA: POST /drive
 * URL Final (exemplo): https://api.fluxo-royale.com.br/api/webhooks/drive
 * * É este o endereço exato que teremos de fornecer ao Google Cloud 
 * quando formos registar o Webhook (Passo 1).
 */
router.post('/drive', handleDriveWebhook);

export default router;
