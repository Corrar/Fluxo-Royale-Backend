import { Router } from 'express';
// Importamos as duas funções do controlador
import { handleDriveWebhook, ativarAlarmeDoDrive } from '../controllers/webhook.controller';

const router = Router();

/**
 * ROTA 1: POST /drive
 * Esta é a porta que o Google vai "bater" quando houver uma alteração.
 */
router.post('/drive', handleDriveWebhook);

/**
 * ROTA 2: GET /setup (O "Botão" de Ligar o Alarme)
 * Esta é a rota que tu vais acessar pelo navegador uma única vez
 * para avisar o Google que ele deve começar a vigiar a pasta.
 */
router.get('/setup', ativarAlarmeDoDrive);

export default router;
