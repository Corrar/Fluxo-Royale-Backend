// =============================================================================
// LEDGER DE MOVIMENTAÇÕES DE ESTOQUE (stock_movements)
// =============================================================================
// Histórico imutável de TODA alteração nas colunas quantity_on_hand e
// quantity_reserved da tabela stock, gravado por um TRIGGER no próprio banco.
//
// Por que trigger e não código no controller?
// - Nenhum caminho escapa: qualquer UPDATE/INSERT/DELETE em stock é registado,
//   inclusive alterações feitas por fora do sistema (psql, console do Neon,
//   scripts). Essas aparecem com action = 'FORA_DO_SISTEMA' — é assim que se
//   distingue "bug do sistema" de "mexeram direto no banco".
// - Os controllers apenas DECLARAM o contexto (ação, usuário, documento de
//   origem) via set_config transaction-local; o trigger carimba esse contexto
//   em cada movimento.
//
// Esta função é idempotente e roda a cada boot do servidor.
// =============================================================================

import { pool } from '../db';

export const ensureStockLedger = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS stock_movements (
        id BIGSERIAL PRIMARY KEY,
        product_id UUID,
        on_hand_before NUMERIC NOT NULL DEFAULT 0,
        on_hand_after NUMERIC NOT NULL DEFAULT 0,
        reserved_before NUMERIC NOT NULL DEFAULT 0,
        reserved_after NUMERIC NOT NULL DEFAULT 0,
        on_hand_delta NUMERIC NOT NULL DEFAULT 0,
        reserved_delta NUMERIC NOT NULL DEFAULT 0,
        action TEXT NOT NULL,
        source TEXT,
        user_id TEXT,
        db_user TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await pool.query(`CREATE INDEX IF NOT EXISTS idx_stock_mov_product ON stock_movements (product_id, created_at DESC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_stock_mov_created ON stock_movements (created_at DESC);`);
    await pool.query(`CREATE INDEX IF NOT EXISTS idx_stock_mov_action ON stock_movements (action);`);

    await pool.query(`
      CREATE OR REPLACE FUNCTION fn_log_stock_movement() RETURNS TRIGGER AS $$
      DECLARE
        v_action TEXT;
        v_user TEXT;
        v_source TEXT;
        v_oh_before NUMERIC; v_oh_after NUMERIC;
        v_rv_before NUMERIC; v_rv_after NUMERIC;
        v_product UUID;
      BEGIN
        IF (TG_OP = 'INSERT') THEN
          v_oh_before := 0; v_rv_before := 0;
          v_oh_after := COALESCE(NEW.quantity_on_hand, 0);
          v_rv_after := COALESCE(NEW.quantity_reserved, 0);
          v_product := NEW.product_id;
        ELSIF (TG_OP = 'UPDATE') THEN
          v_oh_before := COALESCE(OLD.quantity_on_hand, 0);
          v_rv_before := COALESCE(OLD.quantity_reserved, 0);
          v_oh_after := COALESCE(NEW.quantity_on_hand, 0);
          v_rv_after := COALESCE(NEW.quantity_reserved, 0);
          v_product := NEW.product_id;
        ELSE
          v_oh_before := COALESCE(OLD.quantity_on_hand, 0);
          v_rv_before := COALESCE(OLD.quantity_reserved, 0);
          v_oh_after := 0; v_rv_after := 0;
          v_product := OLD.product_id;
        END IF;

        -- Só regista quando as quantidades realmente mudaram
        IF v_oh_before = v_oh_after AND v_rv_before = v_rv_after THEN
          RETURN NULL;
        END IF;

        -- Contexto declarado pelo controller na transação (vazio = fora do sistema)
        v_action := NULLIF(current_setting('fluxo.audit_action', true), '');
        v_user   := NULLIF(current_setting('fluxo.audit_user', true), '');
        v_source := NULLIF(current_setting('fluxo.audit_source', true), '');

        INSERT INTO stock_movements (
          product_id, on_hand_before, on_hand_after, reserved_before, reserved_after,
          on_hand_delta, reserved_delta, action, source, user_id, db_user
        ) VALUES (
          v_product, v_oh_before, v_oh_after, v_rv_before, v_rv_after,
          v_oh_after - v_oh_before, v_rv_after - v_rv_before,
          COALESCE(v_action, 'FORA_DO_SISTEMA'), v_source, v_user, current_user
        );
        RETURN NULL;
      END;
      $$ LANGUAGE plpgsql;
    `);

    await pool.query(`DROP TRIGGER IF EXISTS trg_stock_movements ON stock;`);
    await pool.query(`
      CREATE TRIGGER trg_stock_movements
      AFTER INSERT OR UPDATE OR DELETE ON stock
      FOR EACH ROW EXECUTE FUNCTION fn_log_stock_movement();
    `);

    console.log('📒 Ledger de movimentações de estoque (stock_movements) pronto.');
  } catch (err) {
    console.error('❌ Falha ao preparar o ledger de movimentações de estoque:', err);
  }
};
