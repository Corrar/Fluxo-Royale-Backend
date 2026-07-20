-- =============================================================================
-- RECONCILIAÇÃO DE RESERVAS DE ESTOQUE — Fluxo Royale
-- =============================================================================
-- Os bugs corrigidos em 2026-07 (reserva fantasma de itens 3D, entrega dupla,
-- clamps GREATEST(0) escondendo inconsistências, etc.) provavelmente deixaram
-- o campo stock.quantity_reserved fora da realidade.
--
-- Este script recalcula quantity_reserved a partir dos documentos ABERTOS:
--   - Solicitações em 'aberto'/'aprovado' (itens 3D: só a parte que não está
--     pendente no Kanban, pois essa parte ainda não foi produzida/reservada)
--   - Separações em 'em_separacao' (coluna quantity = o que foi reservado)
--   - Reposições em 'em_preparo'
--   - Viagens ainda não reconciliadas
--
-- ⚠️ Rode em horário de baixo movimento, dentro de uma transação.
--    Primeiro rode o SELECT de auditoria para ver as divergências.
-- =============================================================================

-- ---------- 1) AUDITORIA: veja as divergências antes de aplicar ----------
WITH reservas AS (
  SELECT product_id, SUM(qty) AS total FROM (
    SELECT ri.product_id,
           CASE WHEN COALESCE(p.is_3d, false) THEN
             GREATEST(0, ri.quantity_requested - COALESCE((
               SELECT SUM(d.quantity) FROM demands_3d d
               WHERE d.request_id = ri.request_id
                 AND d.product_id = ri.product_id
                 AND d.status != 'Concluída'), 0))
           ELSE COALESCE(ri.quantity_delivered, ri.quantity_requested) END AS qty
    FROM request_items ri
    JOIN requests r ON r.id = ri.request_id
    LEFT JOIN products p ON p.id = ri.product_id
    WHERE r.status IN ('aberto', 'aprovado') AND ri.product_id IS NOT NULL
    UNION ALL
    SELECT si.product_id, si.quantity
    FROM separation_items si
    JOIN separations s ON s.id = si.separation_id
    WHERE s.status = 'em_separacao'
    UNION ALL
    SELECT ri2.product_id, ri2.quantity
    FROM replenishment_items ri2
    JOIN replenishments rep ON rep.id = ri2.replenishment_id
    WHERE rep.status = 'em_preparo'
    UNION ALL
    SELECT ti.product_id, ti.quantity_out
    FROM travel_order_items ti
    JOIN travel_orders t ON t.id = ti.travel_order_id
    WHERE t.status != 'reconciled'
  ) x
  GROUP BY product_id
)
SELECT p.sku, p.name,
       s.quantity_on_hand,
       s.quantity_reserved  AS reservado_atual,
       COALESCE(r.total, 0) AS reservado_correto,
       s.quantity_reserved - COALESCE(r.total, 0) AS divergencia
FROM stock s
JOIN products p ON p.id = s.product_id
LEFT JOIN reservas r ON r.product_id = s.product_id
WHERE s.quantity_reserved IS DISTINCT FROM COALESCE(r.total, 0)
ORDER BY ABS(s.quantity_reserved - COALESCE(r.total, 0)) DESC;

-- ---------- 2) CORREÇÃO: aplica o valor recalculado ----------
-- Descomente o bloco abaixo depois de conferir a auditoria acima.
/*
BEGIN;

WITH reservas AS (
  SELECT product_id, SUM(qty) AS total FROM (
    SELECT ri.product_id,
           CASE WHEN COALESCE(p.is_3d, false) THEN
             GREATEST(0, ri.quantity_requested - COALESCE((
               SELECT SUM(d.quantity) FROM demands_3d d
               WHERE d.request_id = ri.request_id
                 AND d.product_id = ri.product_id
                 AND d.status != 'Concluída'), 0))
           ELSE COALESCE(ri.quantity_delivered, ri.quantity_requested) END AS qty
    FROM request_items ri
    JOIN requests r ON r.id = ri.request_id
    LEFT JOIN products p ON p.id = ri.product_id
    WHERE r.status IN ('aberto', 'aprovado') AND ri.product_id IS NOT NULL
    UNION ALL
    SELECT si.product_id, si.quantity
    FROM separation_items si
    JOIN separations s ON s.id = si.separation_id
    WHERE s.status = 'em_separacao'
    UNION ALL
    SELECT ri2.product_id, ri2.quantity
    FROM replenishment_items ri2
    JOIN replenishments rep ON rep.id = ri2.replenishment_id
    WHERE rep.status = 'em_preparo'
    UNION ALL
    SELECT ti.product_id, ti.quantity_out
    FROM travel_order_items ti
    JOIN travel_orders t ON t.id = ti.travel_order_id
    WHERE t.status != 'reconciled'
  ) x
  GROUP BY product_id
),
alvo AS (
  SELECT s.id, COALESCE(r.total, 0) AS total
  FROM stock s
  LEFT JOIN reservas r ON r.product_id = s.product_id
)
UPDATE stock s
SET quantity_reserved = a.total
FROM alvo a
WHERE s.id = a.id AND s.quantity_reserved IS DISTINCT FROM a.total;

COMMIT;
*/
