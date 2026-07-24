// =============================================================================
// CUSTOS E PRECIFICAÇÃO DA FÁBRICA 3D
// =============================================================================
// Espelha o cálculo do protótipo "royale_fabrica3d": custo real por peça
// (material + energia + depreciação + manutenção + acabamento) → preço de
// venda sugerido (margem + imposto) → lucro/margem. Alimenta a Calculadora,
// a precificação do catálogo e o dashboard financeiro (retroativo sobre as
// produções já registradas).
// =============================================================================

import { Request, Response } from 'express';
import { pool } from '../db';

// -----------------------------------------------------------------------------
// Núcleo do cálculo (puro) — mesma fórmula usada no frontend (mantê-las iguais)
// -----------------------------------------------------------------------------
const n = (v: any): number => {
  const x = parseFloat(String(v).replace(',', '.'));
  return isFinite(x) ? x : 0;
};

export interface CostConfig { energia_kwh: any; imposto_perc: any; margem_perc: any; mao_obra_hora: any; perda_perc: any; }

// piece: { filament_grams (peso), production_minutes (tempo), finishing_minutes (acabamento) }
export const computeCost = (piece: any, filament: any, printer: any, config: CostConfig) => {
  const gramasBase = n(piece?.filament_grams);
  const gramas = gramasBase * (1 + n(config?.perda_perc) / 100);
  const horas = n(piece?.production_minutes) / 60;

  const custoFilamento = filament ? (gramas / 1000) * n(filament.preco_kg) : 0;
  const custoEnergia = printer ? (n(printer.potencia_w) / 1000) * horas * n(config?.energia_kwh) : 0;
  const custoDepreciacao = printer ? (n(printer.valor) / (n(printer.vida_horas) || 1)) * horas : 0;
  const custoManutencao = printer ? (n(printer.manutencao_ano) / (n(printer.horas_ano) || 1)) * horas : 0;
  const custoAcabamento = (n(piece?.finishing_minutes) / 60) * n(config?.mao_obra_hora);

  const custoTotal = custoFilamento + custoEnergia + custoDepreciacao + custoManutencao + custoAcabamento;

  const margem = n(config?.margem_perc) / 100;
  const imposto = n(config?.imposto_perc) / 100;
  const divisor = 1 - margem - imposto;
  const precoVenda = divisor > 0 ? custoTotal / divisor : custoTotal;
  const valorImposto = precoVenda * imposto;
  const lucro = precoVenda - custoTotal - valorImposto;

  return {
    custoFilamento, custoEnergia, custoDepreciacao, custoManutencao, custoAcabamento,
    custoTotal, precoVenda, valorImposto, lucro,
    margemReal: precoVenda > 0 ? (lucro / precoVenda) * 100 : 0,
    gramasReais: gramas,
  };
};

// -----------------------------------------------------------------------------
// FILAMENTOS
// -----------------------------------------------------------------------------
export const getFilaments = async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM filaments_3d ORDER BY nome ASC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Erro ao buscar filamentos' }); }
};

export const createFilament = async (req: Request, res: Response) => {
  const { nome, marca, preco_kg, densidade, cor } = req.body;
  if (!nome || !String(nome).trim()) return res.status(400).json({ error: 'Informe o nome do filamento.' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO filaments_3d (nome, marca, preco_kg, densidade, cor) VALUES ($1,$2,$3,$4,$5) RETURNING *`,
      [nome, marca || null, n(preco_kg), densidade != null ? n(densidade) : null, cor || null]
    );
    res.status(201).json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'Erro ao criar filamento' }); }
};

export const updateFilament = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { nome, marca, preco_kg, densidade, cor } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE filaments_3d SET nome=$1, marca=$2, preco_kg=$3, densidade=$4, cor=$5 WHERE id=$6 RETURNING *`,
      [nome, marca || null, n(preco_kg), densidade != null ? n(densidade) : null, cor || null, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Filamento não encontrado' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'Erro ao atualizar filamento' }); }
};

export const deleteFilament = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    // Desvincula das peças que o usavam para não deixar referência órfã
    await pool.query('UPDATE products SET filament_id = NULL WHERE filament_id = $1', [id]);
    await pool.query('DELETE FROM filaments_3d WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Erro ao excluir filamento' }); }
};

// -----------------------------------------------------------------------------
// IMPRESSORAS
// -----------------------------------------------------------------------------
export const getPrinters = async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM printers_3d ORDER BY nome ASC');
    res.json(rows);
  } catch (e) { res.status(500).json({ error: 'Erro ao buscar impressoras' }); }
};

export const createPrinter = async (req: Request, res: Response) => {
  const { nome, valor, vida_horas, potencia_w, manutencao_ano, horas_ano } = req.body;
  if (!nome || !String(nome).trim()) return res.status(400).json({ error: 'Informe o nome da impressora.' });
  try {
    const { rows } = await pool.query(
      `INSERT INTO printers_3d (nome, valor, vida_horas, potencia_w, manutencao_ano, horas_ano)
       VALUES ($1,$2,$3,$4,$5,$6) RETURNING *`,
      [nome, n(valor), n(vida_horas) || 15000, n(potencia_w) || 350, n(manutencao_ano), n(horas_ano) || 4000]
    );
    res.status(201).json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'Erro ao criar impressora' }); }
};

export const updatePrinter = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { nome, valor, vida_horas, potencia_w, manutencao_ano, horas_ano } = req.body;
  try {
    const { rows } = await pool.query(
      `UPDATE printers_3d SET nome=$1, valor=$2, vida_horas=$3, potencia_w=$4, manutencao_ano=$5, horas_ano=$6 WHERE id=$7 RETURNING *`,
      [nome, n(valor), n(vida_horas) || 15000, n(potencia_w) || 350, n(manutencao_ano), n(horas_ano) || 4000, id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'Impressora não encontrada' });
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'Erro ao atualizar impressora' }); }
};

export const deletePrinter = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    await pool.query('UPDATE products SET printer_id = NULL WHERE printer_id = $1', [id]);
    await pool.query('DELETE FROM printers_3d WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Erro ao excluir impressora' }); }
};

// -----------------------------------------------------------------------------
// CONFIGURAÇÃO GLOBAL (singleton)
// -----------------------------------------------------------------------------
export const getConfig3D = async (_req: Request, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT * FROM config_3d WHERE id = 1');
    res.json(rows[0] || {});
  } catch (e) { res.status(500).json({ error: 'Erro ao buscar configuração 3D' }); }
};

export const updateConfig3D = async (req: Request, res: Response) => {
  const { energia_kwh, imposto_perc, margem_perc, mao_obra_hora, perda_perc } = req.body;
  try {
    const { rows } = await pool.query(
      `INSERT INTO config_3d (id, energia_kwh, imposto_perc, margem_perc, mao_obra_hora, perda_perc)
       VALUES (1, $1, $2, $3, $4, $5)
       ON CONFLICT (id) DO UPDATE SET
         energia_kwh = $1, imposto_perc = $2, margem_perc = $3, mao_obra_hora = $4, perda_perc = $5
       RETURNING *`,
      [n(energia_kwh), n(imposto_perc), n(margem_perc), n(mao_obra_hora), n(perda_perc)]
    );
    res.json(rows[0]);
  } catch (e) { res.status(500).json({ error: 'Erro ao salvar configuração 3D' }); }
};

// -----------------------------------------------------------------------------
// Helpers de carga (config + mapas de filamento/impressora)
// -----------------------------------------------------------------------------
const loadCostContext = async () => {
  const [cfgRes, filRes, prtRes] = await Promise.all([
    pool.query('SELECT * FROM config_3d WHERE id = 1'),
    pool.query('SELECT * FROM filaments_3d'),
    pool.query('SELECT * FROM printers_3d'),
  ]);
  const config = cfgRes.rows[0] || { energia_kwh: 0, imposto_perc: 0, margem_perc: 0, mao_obra_hora: 0, perda_perc: 0 };
  const filaments = new Map(filRes.rows.map((f: any) => [String(f.id), f]));
  const printers = new Map(prtRes.rows.map((p: any) => [String(p.id), p]));
  // Padrão = primeiro cadastrado. Peças sem vínculo usam este padrão para já
  // terem um custo real (com o peso/tempo que a peça já tem), como no protótipo.
  const defaultFilament = filRes.rows[0] || null;
  const defaultPrinter = prtRes.rows[0] || null;
  return { config, filaments, printers, defaultFilament, defaultPrinter };
};

// -----------------------------------------------------------------------------
// PRECIFICAÇÃO DO CATÁLOGO — todas as peças 3D com custo/preço/lucro calculado
// -----------------------------------------------------------------------------
export const getPartsCosting = async (_req: Request, res: Response) => {
  try {
    const { config, filaments, printers, defaultFilament, defaultPrinter } = await loadCostContext();
    const { rows } = await pool.query(`
      SELECT id, sku, name, image_url, production_minutes, filament_grams,
             finishing_minutes, filament_id, printer_id, unit_price
      FROM products WHERE is_3d = true ORDER BY name ASC
    `);
    const out = rows.map((p: any) => {
      const filVinc = p.filament_id ? filaments.get(String(p.filament_id)) : null;
      const prtVinc = p.printer_id ? printers.get(String(p.printer_id)) : null;
      const fil = filVinc || defaultFilament; // fallback para o padrão
      const prt = prtVinc || defaultPrinter;
      const c = computeCost(p, fil, prt, config);
      return {
        ...p,
        filament_nome: fil?.nome || null,
        printer_nome: prt?.nome || null,
        usando_filamento_padrao: !filVinc && !!fil,
        usando_impressora_padrao: !prtVinc && !!prt,
        custo: c.custoTotal,
        preco_venda: c.precoVenda,
        lucro: c.lucro,
        margem_real: c.margemReal,
        breakdown: c,
      };
    });
    res.json(out);
  } catch (e) { res.status(500).json({ error: 'Erro ao calcular precificação das peças' }); }
};

// Atualiza os campos de custo de UMA peça 3D (filamento, impressora, acabamento,
// e opcionalmente peso/tempo). Não mexe em estoque.
export const updatePartCosting = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { filament_id, printer_id, finishing_minutes, filament_grams, production_minutes } = req.body;
  try {
    await pool.query(
      `UPDATE products SET
         filament_id = $1,
         printer_id = $2,
         finishing_minutes = COALESCE($3, finishing_minutes),
         filament_grams = COALESCE($4, filament_grams),
         production_minutes = COALESCE($5, production_minutes)
       WHERE id = $6 AND is_3d = true`,
      [
        filament_id || null,
        printer_id || null,
        finishing_minutes != null ? n(finishing_minutes) : null,
        filament_grams != null ? n(filament_grams) : null,
        production_minutes != null ? n(production_minutes) : null,
        id,
      ]
    );
    res.json({ success: true });
  } catch (e) { res.status(500).json({ error: 'Erro ao atualizar custos da peça' }); }
};

// -----------------------------------------------------------------------------
// DASHBOARD FINANCEIRO — retroativo sobre as produções já registradas
// -----------------------------------------------------------------------------
export const getFinancialReport = async (req: Request, res: Response) => {
  try {
    const { from, to } = req.query as { from?: string; to?: string };
    const { config, filaments, printers, defaultFilament, defaultPrinter } = await loadCostContext();

    // Produções + dados de custo da peça (uma linha por produção registrada)
    const params: any[] = [];
    let where = 'WHERE pr.is_3d = true';
    if (from) { params.push(from); where += ` AND p3d.date >= $${params.length}`; }
    if (to) { params.push(to); where += ` AND p3d.date <= $${params.length}`; }

    const { rows } = await pool.query(`
      SELECT p3d.id, p3d.quantity, p3d.date, p3d.total_minutes, p3d.filament_grams AS prod_gramas,
             pr.id AS product_id, pr.name, pr.sku, pr.production_minutes, pr.filament_grams,
             pr.finishing_minutes, pr.filament_id, pr.printer_id
      FROM productions_3d p3d
      JOIN products pr ON p3d.product_id = pr.id
      ${where}
      ORDER BY p3d.date ASC
    `, params);

    let fat = 0, custo = 0, imposto = 0, lucro = 0, horas = 0, gramas = 0, unidades = 0;
    const porMes: Record<string, { fat: number; lucro: number; custo: number }> = {};
    const porPeca: Record<string, { name: string; sku: string; q: number; lucro: number; receita: number; custo: number }> = {};

    for (const r of rows) {
      const fil = (r.filament_id ? filaments.get(String(r.filament_id)) : null) || defaultFilament;
      const prt = (r.printer_id ? printers.get(String(r.printer_id)) : null) || defaultPrinter;
      const c = computeCost(r, fil, prt, config);
      const q = n(r.quantity);

      const receita = c.precoVenda * q;
      fat += receita;
      custo += c.custoTotal * q;
      imposto += c.valorImposto * q;
      lucro += c.lucro * q;
      horas += (n(r.production_minutes) / 60) * q;
      gramas += c.gramasReais * q;
      unidades += q;

      const mes = (r.date ? new Date(r.date).toISOString() : '').slice(0, 7);
      if (mes) {
        if (!porMes[mes]) porMes[mes] = { fat: 0, lucro: 0, custo: 0 };
        porMes[mes].fat += receita;
        porMes[mes].lucro += c.lucro * q;
        porMes[mes].custo += c.custoTotal * q;
      }

      const pid = String(r.product_id);
      if (!porPeca[pid]) porPeca[pid] = { name: r.name, sku: r.sku, q: 0, lucro: 0, receita: 0, custo: 0 };
      porPeca[pid].q += q;
      porPeca[pid].lucro += c.lucro * q;
      porPeca[pid].receita += receita;
      porPeca[pid].custo += c.custoTotal * q;
    }

    const ranking = Object.values(porPeca).sort((a, b) => b.lucro - a.lucro).slice(0, 10);
    const margem = fat > 0 ? (lucro / fat) * 100 : 0;

    res.json({
      totais: {
        faturamento: fat, custo, imposto, lucro, margem,
        horas, gramas, unidades,
        lucroPorHora: horas > 0 ? lucro / horas : 0,
        ticketMedio: unidades > 0 ? fat / unidades : 0,
      },
      porMes: Object.entries(porMes).sort().map(([mes, v]) => ({ mes, ...v })),
      ranking,
    });
  } catch (e) {
    res.status(500).json({ error: 'Erro ao gerar relatório financeiro 3D' });
  }
};
