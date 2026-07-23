// src/routes/producao3d.routes.ts
import { Router } from 'express';
import {
  get3DParts,
  update3DPartDetails,
  getDemands,
  updateDemandStatus,
  getProductions,
  createProduction, // <-- ADICIONADO: Importação da função de criar
  deleteProduction  // <-- ADICIONADO: Importação da função de apagar
} from '../controllers/producao3d.controller';
import {
  getFilaments, createFilament, updateFilament, deleteFilament,
  getPrinters, createPrinter, updatePrinter, deletePrinter,
  getConfig3D, updateConfig3D,
  getPartsCosting, updatePartCosting, getFinancialReport,
} from '../controllers/producao3dCosts.controller';
import { authenticate, requirePermission } from '../middlewares/auth';

const router = Router();

/**
 * 🛡️ Todas as rotas do módulo 3D exigem autenticação.
 * O middleware verifica o token JWT antes de permitir o acesso.
 */
router.use(authenticate);

// 🔒 Escritas que MOVIMENTAM ESTOQUE exigem a permissão granular do módulo.
// As permissões são gravadas no formato "pagekey:acao" (ex.: producao_3d:add) —
// tem de casar exatamente com o que o frontend usa em canAccess(), senão o
// middleware bloqueia até o admin (que só passa pelo bypass de cargo).
const canAdd3D = requirePermission('producao_3d:add');
const canEdit3D = requirePermission('producao_3d:edit');
const canDelete3D = requirePermission('producao_3d:delete');

// ==========================================
// 🏗️ CATÁLOGO DE PEÇAS 3D (Lê da tabela Products)
// ==========================================

// Lista todos os produtos marcados com 'is_3d = true'
router.get('/parts', get3DParts);

// Atualiza detalhes técnicos (tempo, filamento, foto) de uma peça específica
router.put('/parts/:id', update3DPartDetails);

// ==========================================
// 📋 DEMANDAS KANBAN (Conectado às Solicitações)
// ==========================================

// Lista as solicitações de peças 3D pendentes e em curso
router.get('/demands', getDemands);

// Altera o status de uma demanda (ex: mover de 'Aceita' para 'Concluída') — dá entrada no estoque
router.put('/demands/:id/status', canEdit3D, updateDemandStatus);

// ==========================================
// 📊 HISTÓRICO E MÉTRICAS (Dashboard)
// ==========================================

// Busca os dados de produções finalizadas para gerar os gráficos
router.get('/productions', getProductions);

// 🚀 REGISTRA uma nova produção e dá entrada automática no estoque
router.post('/productions', canAdd3D, createProduction);

// 🗑️ REMOVE um registro de produção e reverte a quantidade no estoque
router.delete('/productions/:id', canDelete3D, deleteProduction);

// ==========================================
// 🧮 CUSTOS E PRECIFICAÇÃO (Fábrica 3D)
// ==========================================
// Leitura liberada a todos do módulo 3D; escrita exige a permissão granular.

// Filamentos
router.get('/filaments', getFilaments);
router.post('/filaments', canAdd3D, createFilament);
router.put('/filaments/:id', canEdit3D, updateFilament);
router.delete('/filaments/:id', canDelete3D, deleteFilament);

// Impressoras
router.get('/printers', getPrinters);
router.post('/printers', canAdd3D, createPrinter);
router.put('/printers/:id', canEdit3D, updatePrinter);
router.delete('/printers/:id', canDelete3D, deletePrinter);

// Configuração global de custos
router.get('/config', getConfig3D);
router.put('/config', canEdit3D, updateConfig3D);

// Precificação das peças + dashboard financeiro
router.get('/costing', getPartsCosting);
router.put('/costing/:id', canEdit3D, updatePartCosting);
router.get('/financial-report', getFinancialReport);

export default router;
