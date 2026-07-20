// =============================================================================
// ÍNDICES DE PERFORMANCE
// =============================================================================
// Cria índices nas colunas mais consultadas (joins, filtros de status/data,
// lookups de produto/OP). Idempotente (IF NOT EXISTS) e roda no boot.
//
// Cada índice é criado isoladamente: se uma tabela não existir num ambiente,
// apenas aquele índice é pulado — os demais continuam. Na PRIMEIRA execução em
// tabelas grandes pode levar alguns segundos; nas seguintes é no-op instantâneo.
// =============================================================================

import { pool } from '../db';

const INDEXES: string[] = [
  // Itens de movimentação — joins e agregações por produto/documento
  `CREATE INDEX IF NOT EXISTS idx_request_items_product ON request_items (product_id)`,
  `CREATE INDEX IF NOT EXISTS idx_request_items_request ON request_items (request_id)`,
  `CREATE INDEX IF NOT EXISTS idx_separation_items_product ON separation_items (product_id)`,
  `CREATE INDEX IF NOT EXISTS idx_separation_items_separation ON separation_items (separation_id)`,
  `CREATE INDEX IF NOT EXISTS idx_replenishment_items_product ON replenishment_items (product_id)`,
  `CREATE INDEX IF NOT EXISTS idx_replenishment_items_replenishment ON replenishment_items (replenishment_id)`,
  `CREATE INDEX IF NOT EXISTS idx_travel_items_product ON travel_order_items (product_id)`,
  `CREATE INDEX IF NOT EXISTS idx_travel_items_order ON travel_order_items (travel_order_id)`,

  // Documentos — filtros de status e data usados em listagens e relatórios
  `CREATE INDEX IF NOT EXISTS idx_requests_status ON requests (status)`,
  `CREATE INDEX IF NOT EXISTS idx_requests_created ON requests (created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_requests_requester ON requests (requester_id)`,
  `CREATE INDEX IF NOT EXISTS idx_requests_cs ON requests (client_service_id)`,
  `CREATE INDEX IF NOT EXISTS idx_separations_status ON separations (status)`,
  `CREATE INDEX IF NOT EXISTS idx_separations_cs ON separations (client_service_id)`,
  `CREATE INDEX IF NOT EXISTS idx_separations_created ON separations (created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_replenishments_status ON replenishments (status)`,
  `CREATE INDEX IF NOT EXISTS idx_replenishments_created ON replenishments (created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_travel_orders_status ON travel_orders (status)`,

  // Produção 3D — liberação de reserva e status do Kanban
  `CREATE INDEX IF NOT EXISTS idx_demands3d_request_product ON demands_3d (request_id, product_id)`,
  `CREATE INDEX IF NOT EXISTS idx_demands3d_status ON demands_3d (status)`,

  // Devoluções de OP
  `CREATE INDEX IF NOT EXISTS idx_op_returns_cs_product ON op_returns (client_service_id, product_id)`,

  // Auditoria — a Central filtra por data, ação e usuário
  `CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs (created_at)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs (action)`,
  `CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs (user_id)`,

  // Catálogo e OPs — lookups muito frequentes por SKU/OP e filtro de ativos
  `CREATE INDEX IF NOT EXISTS idx_products_sku ON products (sku)`,
  `CREATE INDEX IF NOT EXISTS idx_products_active ON products (active)`,
  `CREATE INDEX IF NOT EXISTS idx_client_services_op ON client_services (op_code)`,

  // Entradas por NFe (relatórios e "última movimentação")
  `CREATE INDEX IF NOT EXISTS idx_xml_items_product ON xml_items (product_id)`,
  `CREATE INDEX IF NOT EXISTS idx_xml_items_log ON xml_items (xml_log_id)`,
  `CREATE INDEX IF NOT EXISTS idx_xml_logs_created ON xml_logs (created_at)`,
];

export const ensureIndexes = async () => {
  let created = 0;
  for (const stmt of INDEXES) {
    try {
      await pool.query(stmt);
      created++;
    } catch (err: any) {
      // Tabela/coluna ausente neste ambiente — pula sem derrubar o resto
      console.warn(`⚠️ Índice pulado (${err.code || 'erro'}): ${stmt.split(' ')[5]}`);
    }
  }
  console.log(`🚀 Índices de performance verificados (${created}/${INDEXES.length}).`);
};
