import { Router } from 'express';
import { authenticate, authorizeRole } from '../middlewares/auth';
import { 
  getDashboardStats, 
  getManagerialReports, 
  getRecentTransactions, 
  getAvailableDates, 
  getGeneralReports, 
  getAdminLogs,
  getSettings,      // <-- NOVA IMPORTAÇÃO
  updateSetting     // <-- NOVA IMPORTAÇÃO
} from '../controllers/system.controller';

const router = Router();

// Protege todas as rotas abaixo com autenticação
router.use(authenticate);

// Dashboards e Relatórios
router.get('/dashboard/stats', getDashboardStats);
router.get('/reports/managerial', getManagerialReports);
router.get('/reports/general', getGeneralReports);
router.get('/reports/available-dates', getAvailableDates);
router.get('/transactions/recent', getRecentTransactions);

// Logs
router.get('/admin/logs', getAdminLogs);

// Configurações do Sistema (Aviso de Login, etc.)
router.get('/admin/settings', getSettings);    // <-- NOVA ROTA: Ler as definições
// 🔒 Alterar configurações globais é exclusivo de admin (antes qualquer autenticado gravava)
router.put('/admin/settings', authorizeRole(['admin']), updateSetting);

export default router;
