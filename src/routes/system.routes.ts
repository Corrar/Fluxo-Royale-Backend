import { Router } from 'express';
import { authenticate } from '../middlewares/auth';
import { getDashboardStats, getManagerialReports, getRecentTransactions, getAvailableDates, getGeneralReports, getAdminLogs } from '../controllers/system.controller';

const router = Router();
router.use(authenticate);

// Dashboards e Relatórios
router.get('/dashboard/stats', getDashboardStats);
router.get('/reports/managerial', getManagerialReports);
router.get('/reports/general', getGeneralReports);
router.get('/reports/available-dates', getAvailableDates);
router.get('/transactions/recent', getRecentTransactions);

// Logs
router.get('/admin/logs', getAdminLogs);

export default router;
