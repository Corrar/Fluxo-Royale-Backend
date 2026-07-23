// =============================================================================
// CAMADA DE CUSTOS / PRECIFICAÇÃO DA FÁBRICA 3D
// =============================================================================
// Tabelas de apoio para calcular o custo real de cada peça 3D e o preço de
// venda sugerido (material + energia + depreciação + manutenção + acabamento).
//
// - filaments_3d : catálogo de filamentos (preço por kg, densidade, cor)
// - printers_3d  : parque de impressoras (valor, vida útil, potência, manut.)
// - config_3d    : parâmetros globais (energia, imposto, margem, mão de obra, perda)
// - products.*   : 3 colunas nas peças 3D (filamento, impressora, acabamento)
//
// Idempotente — roda a cada boot. Semeia valores padrão só quando vazio, para
// o operador já começar com uma base editável (mesmos defaults do protótipo).
// =============================================================================

import { pool } from '../db';

export const ensure3DCostTables = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS filaments_3d (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        nome TEXT NOT NULL,
        marca TEXT,
        preco_kg NUMERIC NOT NULL DEFAULT 0,
        densidade NUMERIC,
        cor TEXT,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS printers_3d (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        nome TEXT NOT NULL,
        valor NUMERIC NOT NULL DEFAULT 0,
        vida_horas NUMERIC NOT NULL DEFAULT 15000,
        potencia_w NUMERIC NOT NULL DEFAULT 350,
        manutencao_ano NUMERIC NOT NULL DEFAULT 0,
        horas_ano NUMERIC NOT NULL DEFAULT 4000,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);

    // Linha única de configuração global (singleton id = 1)
    await pool.query(`
      CREATE TABLE IF NOT EXISTS config_3d (
        id INT PRIMARY KEY DEFAULT 1,
        energia_kwh NUMERIC NOT NULL DEFAULT 0.92,
        imposto_perc NUMERIC NOT NULL DEFAULT 6,
        margem_perc NUMERIC NOT NULL DEFAULT 45,
        mao_obra_hora NUMERIC NOT NULL DEFAULT 28,
        perda_perc NUMERIC NOT NULL DEFAULT 5,
        CONSTRAINT config_3d_singleton CHECK (id = 1)
      );
    `);
    await pool.query(`INSERT INTO config_3d (id) VALUES (1) ON CONFLICT (id) DO NOTHING;`);

    // Peças 3D ganham: filamento usado, impressora usada e minutos de acabamento.
    // (peso em gramas e tempo já vivem em products.filament_grams / production_minutes)
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS filament_id UUID;`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS printer_id UUID;`);
    await pool.query(`ALTER TABLE products ADD COLUMN IF NOT EXISTS finishing_minutes NUMERIC DEFAULT 0;`);

    // Semeadura inicial (só quando vazio) — base editável para o operador
    const filCount = await pool.query('SELECT COUNT(*)::int AS n FROM filaments_3d');
    if (filCount.rows[0].n === 0) {
      await pool.query(`
        INSERT INTO filaments_3d (nome, marca, preco_kg, densidade, cor) VALUES
          ('PETG Royale', 'Bambu Lab', 114, 1.27, 'Branco'),
          ('PA6-CF', 'Bambu Lab', 389, 1.17, 'Preto'),
          ('PETG-CF', 'Bambu Lab', 289, 1.25, 'Preto');
      `);
    }

    const prtCount = await pool.query('SELECT COUNT(*)::int AS n FROM printers_3d');
    if (prtCount.rows[0].n === 0) {
      await pool.query(`
        INSERT INTO printers_3d (nome, valor, vida_horas, potencia_w, manutencao_ano, horas_ano) VALUES
          ('H2S — Máquina 01', 22000, 15000, 350, 1800, 4000),
          ('H2S — Máquina 02', 22000, 15000, 350, 1800, 4000);
      `);
    }

    console.log('🧮 Camada de custos/precificação 3D (filaments_3d, printers_3d, config_3d) pronta.');
  } catch (err) {
    console.error('❌ Falha ao preparar a camada de custos 3D:', err);
  }
};
