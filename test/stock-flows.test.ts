import { describe, it, expect, beforeAll, beforeEach, vi } from 'vitest';

// Banco Postgres em memória (pg-mem), criado uma vez e compartilhado com o
// mock de '../src/db' — os controllers rodam as MESMAS queries SQL de produção.
const testDb = vi.hoisted(() => {
  const { newDb, DataType } = require('pg-mem');
  const { randomUUID } = require('crypto');
  const mem = newDb();
  mem.public.registerFunction({
    name: 'gen_random_uuid',
    returns: DataType.uuid,
    // impure: sem isto o pg-mem memoiza o retorno e gera PKs duplicadas quando
    // a mesma transação insere várias linhas com DEFAULT gen_random_uuid().
    impure: true,
    implementation: () => randomUUID(),
  });
  // pg-mem não suporta as subqueries correlacionadas com json_agg/json_build_object
  // usadas apenas para MONTAR RESPOSTAS/LISTAGENS (não tocam no estoque). Interceptamos
  // essas queries e devolvemos um resultado vazio para o controller prosseguir — os
  // UPDATE/SELECT de estoque, que são o objeto do teste, rodam de verdade.
  mem.public.interceptQueries((sql: string) => {
    if (/json_agg|json_build_object/i.test(sql)) {
      return [{ request_items: [], items: [], returns: null, requester: null }];
    }
    return null;
  });
  const pg = mem.adapters.createPg();
  const pool = new pg.Pool();
  return { mem, pool };
});

vi.mock('../src/db', () => ({ pool: testDb.pool }));
// Notificações push dependem de web-push/DB externos — irrelevantes aqui.
vi.mock('../src/utils/notifications', () => ({
  sendPushNotificationToRole: vi.fn(),
  sendPushNotificationToUser: vi.fn(),
}));

import { applySchema, seedProduct, getStock } from './setup/schema';
import { createRequest, updateRequestStatus, deleteRequest } from '../src/controllers/requests.controller';
import { manualWithdrawal, registerReturn } from '../src/controllers/stock.controller';
import { createSeparation, authorizeSeparation } from '../src/controllers/separations.controller';
import { createProduction, updateDemandStatus, getProductions } from '../src/controllers/producao3d.controller';
import { createReplenishment, authorizeReplenishment } from '../src/controllers/replenishments.controller';
import { createTravelOrder, reconcileTravelOrder } from '../src/controllers/travels.controller';
import { computeCost, getFinancialReport, getPartsCosting } from '../src/controllers/producao3dCosts.controller';

const pool = testDb.pool;

// ---- Helpers de req/res ----
const mockRes = () => {
  const res: any = { statusCode: 200 };
  res.status = (c: number) => { res.statusCode = c; return res; };
  res.json = (b: any) => { res.body = b; return res; };
  return res;
};
const mockReq = (over: any = {}) => ({
  body: {}, params: {}, query: {}, headers: {}, socket: {},
  user: { id: 'user-1' }, ...over,
});

const run = async (fn: any, req: any) => {
  const res = mockRes();
  await fn(req, res);
  return res;
};

// Cria o schema + seed base UMA vez e tira um snapshot; antes de cada teste
// restaura o snapshot (reset rápido e limpo — pg-mem recomenda backup/restore).
let snapshot: any;
beforeAll(async () => {
  await applySchema(pool);
  await pool.query(`INSERT INTO profiles (id, name, role, sector) VALUES ('user-1', 'Almox', 'almoxarife', 'Almoxarifado')`);
  snapshot = testDb.mem.backup();
});
beforeEach(() => {
  snapshot.restore();
});

// =========================================================================
// SOLICITAÇÕES — reserva na criação, débito na entrega
// =========================================================================
describe('Solicitações (requests)', () => {
  it('reserva o disponível ao criar (produto não-3D)', async () => {
    const pid = await seedProduct(pool, { onHand: 10, reserved: 0 });
    const res = await run(createRequest, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 4 }] } }));

    expect(res.statusCode).toBe(201);
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(10);   // físico intacto
    expect(s.reserved).toBe(4);  // reservado
  });

  it('rejeita criação quando o disponível é insuficiente', async () => {
    const pid = await seedProduct(pool, { onHand: 3, reserved: 0 });
    const res = await run(createRequest, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 5 }] } }));

    expect(res.statusCode).toBe(400);
    const s = await getStock(pool, pid);
    expect(s.reserved).toBe(0); // nada reservado
  });

  it('não reserva além do já reservado por outro pedido', async () => {
    const pid = await seedProduct(pool, { onHand: 10, reserved: 8 }); // disponível = 2
    const res = await run(createRequest, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 3 }] } }));
    expect(res.statusCode).toBe(400);
  });

  it('entrega debita o físico e libera a reserva', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    const c = await run(createRequest, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 4 }] } }));
    const reqId = c.body.id;

    const res = await run(updateRequestStatus, mockReq({ params: { id: reqId }, body: { status: 'entregue' } }));
    expect(res.statusCode).toBe(200);
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(6);   // 10 - 4
    expect(s.reserved).toBe(0); // reserva liberada
  });

  it('rejeição libera a reserva sem tocar no físico', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    const c = await run(createRequest, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 4 }] } }));
    const res = await run(updateRequestStatus, mockReq({ params: { id: c.body.id }, body: { status: 'rejeitado' } }));
    expect(res.statusCode).toBe(200);
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(10);
    expect(s.reserved).toBe(0);
  });

  it('bloqueia transição inválida (entregar duas vezes)', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    const c = await run(createRequest, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 4 }] } }));
    await run(updateRequestStatus, mockReq({ params: { id: c.body.id }, body: { status: 'entregue' } }));
    const res2 = await run(updateRequestStatus, mockReq({ params: { id: c.body.id }, body: { status: 'entregue' } }));

    expect(res2.statusCode).toBe(500); // erro de transição inválida
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(6); // NÃO debitou de novo
  });
});

// =========================================================================
// RETIRADA MANUAL — consome apenas o saldo livre
// =========================================================================
describe('Retirada manual (manualWithdrawal)', () => {
  it('consome do físico quando há saldo livre', async () => {
    const pid = await seedProduct(pool, { onHand: 10, reserved: 0, tags: JSON.stringify(['epi']) });
    const res = await run(manualWithdrawal, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 3 }] } }));
    expect(res.statusCode).toBe(201);
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(7);
  });

  it('não consome estoque já reservado (bloqueia furo)', async () => {
    const pid = await seedProduct(pool, { onHand: 10, reserved: 8, tags: JSON.stringify(['epi']) }); // livre = 2
    const res = await run(manualWithdrawal, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 5 }] } }));
    expect(res.statusCode).toBe(500); // estoque disponível insuficiente
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(10); // intacto
  });
});

// =========================================================================
// SEPARAÇÕES — reservar e entregar
// =========================================================================
describe('Separações', () => {
  it('reservar aumenta a reserva; entregar debita o físico', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    const create = await run(createSeparation, mockReq({ body: { client_name: 'ACME', production_order: 'OP1', destination: 'Elétrica', items: [{ product_id: pid, quantity: 5 }] } }));
    expect(create.statusCode).toBe(201);
    const sepId = (await pool.query('SELECT id FROM separations LIMIT 1')).rows[0].id;
    const itemId = (await pool.query('SELECT id FROM separation_items LIMIT 1')).rows[0].id;

    await run(authorizeSeparation, mockReq({ params: { id: sepId }, body: { action: 'reservar', items: [{ id: itemId, quantity: 5 }] } }));
    let s = await getStock(pool, pid);
    expect(s.reserved).toBe(5);
    expect(s.onHand).toBe(10);

    await run(authorizeSeparation, mockReq({ params: { id: sepId }, body: { action: 'entregar', items: [{ id: itemId, quantity: 5 }] } }));
    s = await getStock(pool, pid);
    expect(s.onHand).toBe(5);   // debitou
    expect(s.reserved).toBe(0); // liberou
  });
});

// =========================================================================
// PRODUÇÃO 3D — entrada automática no estoque
// =========================================================================
describe('Produção 3D', () => {
  it('registrar produção dá entrada no estoque físico', async () => {
    const pid = await seedProduct(pool, { onHand: 2, is3d: true });
    const res = await run(createProduction, mockReq({ body: { partId: pid, quantity: 5, totalMinutes: 60, filamentGrams: 100, date: '2026-01-01T00:00:00Z' } }));
    expect(res.statusCode).toBe(201);
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(7); // 2 + 5
  });

  it('rejeita quantidade inválida', async () => {
    const pid = await seedProduct(pool, { onHand: 0, is3d: true });
    const res = await run(createProduction, mockReq({ body: { partId: pid, quantity: 0, totalMinutes: 10, filamentGrams: 10, date: '2026-01-01T00:00:00Z' } }));
    expect(res.statusCode).toBe(400);
  });

  it('demanda "Concluída" dá entrada UMA vez (não duplica ao reprocessar)', async () => {
    const pid = await seedProduct(pool, { onHand: 0, is3d: true });
    const dem = await pool.query(`INSERT INTO demands_3d (product_id, quantity, status) VALUES ($1, 5, 'Pendente') RETURNING id`, [pid]);
    const demId = dem.rows[0].id;

    await run(updateDemandStatus, mockReq({ params: { id: demId }, body: { status: 'Concluída' } }));
    let s = await getStock(pool, pid);
    expect(s.onHand).toBe(5);

    // Reprocessar "Concluída" (oldStatus já é Concluída) não credita de novo
    await run(updateDemandStatus, mockReq({ params: { id: demId }, body: { status: 'Concluída' } }));
    s = await getStock(pool, pid);
    expect(s.onHand).toBe(5);
  });

  it('toda solicitação 3D cria uma demanda no Quadro (mesmo sem estoque)', async () => {
    const pid = await seedProduct(pool, { onHand: 0, is3d: true });
    const c = await run(createRequest, mockReq({ body: { sector: '3D', op_code: undefined, items: [{ product_id: pid, quantity: 3 }] } }));
    expect(c.statusCode).toBe(201);

    const dem = await pool.query('SELECT quantity, status, request_id FROM demands_3d WHERE request_id = $1', [c.body.id]);
    expect(dem.rows.length).toBe(1);
    expect(Number(dem.rows[0].quantity)).toBe(3); // a produzir = 3
    expect(dem.rows[0].status).toBe('Em análise'); // cai na Fila do operador 3D
  });

  it('concluir a demanda produz E dá baixa na solicitação (pedido 100% 3D)', async () => {
    const pid = await seedProduct(pool, { onHand: 0, is3d: true });
    const c = await run(createRequest, mockReq({ body: { sector: '3D', items: [{ product_id: pid, quantity: 3 }] } }));
    const demId = (await pool.query('SELECT id FROM demands_3d WHERE request_id = $1', [c.body.id])).rows[0].id;

    const r = await run(updateDemandStatus, mockReq({ params: { id: demId }, body: { status: 'Concluída' } }));
    expect(r.statusCode).toBe(200);
    expect(r.body.delivered).toBe(true);

    // Produziu 3 e entregou 3 → estoque zerado, sem reserva fantasma
    const s = await getStock(pool, pid);
    expect(s.onHand).toBe(0);
    expect(s.reserved).toBe(0);

    // Solicitação recebeu baixa automaticamente
    const req = await pool.query('SELECT status FROM requests WHERE id = $1', [c.body.id]);
    expect(req.rows[0].status).toBe('entregue');
  });

  it('finalizar no Quadro registra a produção no dia, com tempo/filamento/operador', async () => {
    // Peça com tempo e filamento definidos no catálogo
    const pid = await seedProduct(pool, { onHand: 0, is3d: true });
    await pool.query('UPDATE products SET production_minutes = 30, filament_grams = 20 WHERE id = $1', [pid]);
    const dem = await pool.query(`INSERT INTO demands_3d (product_id, quantity, status) VALUES ($1, 4, 'Em desenvolvimento') RETURNING id`, [pid]);

    const before = Date.now();
    await run(updateDemandStatus, mockReq({ params: { id: dem.rows[0].id }, body: { status: 'Concluída' } }));

    // Aparece via a MESMA rota que a página Histórico de Produção consome
    const hist = await run(getProductions, mockReq({}));
    const rec = hist.body.find((p: any) => String(p.demandId) === String(dem.rows[0].id));
    expect(rec).toBeTruthy();
    expect(Number(rec.quantity)).toBe(4);
    expect(Number(rec.totalMinutes)).toBe(120);   // 30 min * 4
    expect(Number(rec.filamentGrams)).toBe(80);   // 20 g * 4
    expect(rec.operator).toBe('Almox');           // nome do operador (join profiles)
    // Data = momento da finalização (agrupada no dia de hoje no Histórico)
    expect(new Date(rec.date).getTime()).toBeGreaterThanOrEqual(before - 1000);
  });

  it('não credita em dobro: produção manual + finalizar no Quadro', async () => {
    const pid = await seedProduct(pool, { onHand: 0, is3d: true });
    const dem = await pool.query(`INSERT INTO demands_3d (product_id, quantity, status) VALUES ($1, 5, 'Em desenvolvimento') RETURNING id`, [pid]);
    const demId = dem.rows[0].id;

    // Operador registra a produção pela página de Produção (credita +5)
    await run(createProduction, mockReq({ body: { partId: pid, demandId: demId, quantity: 5, totalMinutes: 50, filamentGrams: 80, date: '2026-01-01T00:00:00Z' } }));
    let s = await getStock(pool, pid);
    expect(s.onHand).toBe(5);

    // Depois finaliza no Quadro: NÃO credita de novo (produção já existe)
    await run(updateDemandStatus, mockReq({ params: { id: demId }, body: { status: 'Concluída' } }));
    s = await getStock(pool, pid);
    expect(s.onHand).toBe(5); // continua 5, não 10

    // E bloqueia registrar produção de novo p/ uma demanda já concluída
    const blocked = await run(createProduction, mockReq({ body: { partId: pid, demandId: demId, quantity: 5, totalMinutes: 50, filamentGrams: 80, date: '2026-01-01T00:00:00Z' } }));
    expect(blocked.statusCode).toBe(409);
    s = await getStock(pool, pid);
    expect(s.onHand).toBe(5);
  });

  it('baixa 3D com peça já em estoque consome a prateleira sem furo', async () => {
    const pid = await seedProduct(pool, { onHand: 5, is3d: true });
    const c = await run(createRequest, mockReq({ body: { sector: '3D', items: [{ product_id: pid, quantity: 2 }] } }));
    // reservou 2 da prateleira, nada a produzir (missingQty = 0)
    let s = await getStock(pool, pid);
    expect(s.reserved).toBe(2);
    const demId = (await pool.query('SELECT id FROM demands_3d WHERE request_id = $1', [c.body.id])).rows[0].id;

    await run(updateDemandStatus, mockReq({ params: { id: demId }, body: { status: 'Concluída' } }));
    s = await getStock(pool, pid);
    expect(s.onHand).toBe(3);    // 5 - 2 entregues
    expect(s.reserved).toBe(0);  // reserva liberada
    const req = await pool.query('SELECT status FROM requests WHERE id = $1', [c.body.id]);
    expect(req.rows[0].status).toBe('entregue');
  });
});

// Nota: a regra de "OP obrigatória por tags" do manualWithdrawal usa
// `WHERE id = ANY($1::uuid[])`, cast de array que o pg-mem não executa. É
// validação de negócio (não de estoque) e fica coberta pelos testes de
// produção quando houver um Postgres real no CI.

// =========================================================================
// REPOSIÇÕES — reservar (por incremento) e entregar
// =========================================================================
describe('Reposições', () => {
  it('reservar por incremento e entregar debita o físico', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    await run(createReplenishment, mockReq({ body: { order_number: 'NF1', client_name: 'ACME', city_state: 'SP', items: [{ product_id: pid, qty_requested: 4 }] } }));
    const repId = (await pool.query('SELECT id FROM replenishments LIMIT 1')).rows[0].id;
    const itemId = (await pool.query('SELECT id FROM replenishment_items LIMIT 1')).rows[0].id;

    await run(authorizeReplenishment, mockReq({ params: { id: repId }, body: { action: 'reservar', items: [{ id: itemId, increment: 4 }] } }));
    let s = await getStock(pool, pid);
    expect(s.reserved).toBe(4);

    await run(authorizeReplenishment, mockReq({ params: { id: repId }, body: { action: 'entregar', items: [{ id: itemId, increment: 0 }] } }));
    s = await getStock(pool, pid);
    expect(s.onHand).toBe(6);
    expect(s.reserved).toBe(0);
  });
});

// =========================================================================
// VIAGENS — reserva na criação, consumo no acerto
// =========================================================================
describe('Viagens', () => {
  it('cria reservando e o acerto baixa o físico do consumido', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    await run(createTravelOrder, mockReq({ body: { technicians: 'João', city: 'SP', items: [{ product_id: pid, quantity: 6 }] } }));
    const toId = (await pool.query('SELECT id FROM travel_orders LIMIT 1')).rows[0].id;
    let s = await getStock(pool, pid);
    expect(s.reserved).toBe(6);

    // Volta 2, consome 4 → físico 10-4=6, reserva liberada
    await run(reconcileTravelOrder, mockReq({ params: { id: toId }, body: { returnedItems: [{ product_id: pid, returnedQuantity: 2 }] } }));
    s = await getStock(pool, pid);
    expect(s.onHand).toBe(6);
    expect(s.reserved).toBe(0);
  });
});

// =========================================================================
// CANCELAMENTO DE SOLICITAÇÃO — libera a reserva
// =========================================================================
describe('Cancelamento de solicitação', () => {
  it('cancelar um pedido aberto libera a reserva', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    const c = await run(createRequest, mockReq({ body: { sector: 'Elétrica', items: [{ product_id: pid, quantity: 4 }] } }));
    expect((await getStock(pool, pid)).reserved).toBe(4);

    const res = await run(deleteRequest, mockReq({ params: { id: c.body.id } }));
    expect(res.statusCode).toBe(200);
    const s = await getStock(pool, pid);
    expect(s.reserved).toBe(0);
    expect(s.onHand).toBe(10);
  });
});

// =========================================================================
// DEVOLUÇÃO DE OP — não permite devolver mais do que foi retirado
// =========================================================================
describe('Devolução de OP', () => {
  it('bloqueia devolução acima do retirado na OP', async () => {
    const pid = await seedProduct(pool, { onHand: 10 });
    const op = await pool.query(`INSERT INTO client_services (op_code, status) VALUES ('OP-1', 'aberta') RETURNING id`);
    const opId = op.rows[0].id;
    // Retirou 3 nessa OP
    await run(manualWithdrawal, mockReq({ body: { sector: 'Elétrica', op_code: 'OP-1', items: [{ product_id: pid, quantity: 3 }] } }));

    // Tenta devolver 5 (mais que os 3 retirados)
    const res = await run(registerReturn, mockReq({ body: { op_code: 'OP-1', returns: [{ product_id: pid, quantity: 5, observation: 'x' }] } }));
    expect(res.statusCode).toBe(400);

    // Devolver 2 (dentro do limite) funciona e credita o físico
    const physBefore = (await getStock(pool, pid)).onHand; // 10 - 3 = 7
    const ok = await run(registerReturn, mockReq({ body: { op_code: 'OP-1', returns: [{ product_id: pid, quantity: 2, observation: 'x' }] } }));
    expect(ok.statusCode).toBe(201);
    expect((await getStock(pool, pid)).onHand).toBe(physBefore + 2);
  });
});

// =========================================================================
// CUSTOS 3D — fórmula de custo/preço/lucro (protótipo royale_fabrica3d)
// =========================================================================
describe('Custos e precificação 3D', () => {
  const config = { energia_kwh: 0.92, imposto_perc: 6, margem_perc: 45, mao_obra_hora: 28, perda_perc: 5 };
  const filament = { preco_kg: 114 };
  const printer = { valor: 22000, vida_horas: 15000, potencia_w: 350, manutencao_ano: 1800, horas_ano: 4000 };

  it('calcula custo, preço de venda e margem corretamente', () => {
    const piece = { filament_grams: 42, production_minutes: 90, finishing_minutes: 5 };
    const c = computeCost(piece, filament, printer, config);
    expect(c.custoTotal).toBeCloseTo(10.7187, 2);
    expect(c.precoVenda).toBeCloseTo(21.8749, 2);
    expect(c.lucro).toBeCloseTo(9.8437, 2);
    expect(c.margemReal).toBeCloseTo(45, 1); // margem configurada se realiza
  });

  it('sem impressora/filamento não quebra (custos zeram)', () => {
    const c = computeCost({ filament_grams: 10, production_minutes: 30, finishing_minutes: 0 }, null, null, config);
    expect(c.custoFilamento).toBe(0);
    expect(c.custoEnergia).toBe(0);
    expect(c.custoTotal).toBe(0);
  });

  it('aplica a perda percentual sobre o filamento', () => {
    const semPerda = computeCost({ filament_grams: 100, production_minutes: 0, finishing_minutes: 0 }, filament, null, { ...config, perda_perc: 0 });
    const comPerda = computeCost({ filament_grams: 100, production_minutes: 0, finishing_minutes: 0 }, filament, null, { ...config, perda_perc: 10 });
    expect(comPerda.custoFilamento).toBeCloseTo(semPerda.custoFilamento * 1.1, 4);
  });
});

// =========================================================================
// CUSTOS 3D — precificação e relatório financeiro com dados reais (fallback)
// =========================================================================
describe('Precificação e financeiro 3D (integração)', () => {
  const seedCostBase = async () => {
    await pool.query(`INSERT INTO config_3d (id, energia_kwh, imposto_perc, margem_perc, mao_obra_hora, perda_perc) VALUES (1, 0.92, 6, 45, 28, 5)`);
    await pool.query(`INSERT INTO filaments_3d (nome, preco_kg) VALUES ('PETG', 114)`);
    await pool.query(`INSERT INTO printers_3d (nome, valor, vida_horas, potencia_w, manutencao_ano, horas_ano) VALUES ('H2S', 22000, 15000, 350, 1800, 4000)`);
  };

  it('peça SEM vínculo usa filamento/impressora padrão e tem custo real', async () => {
    await seedCostBase();
    const pid = await seedProduct(pool, { onHand: 0, is3d: true, name: 'Talisca' });
    await pool.query('UPDATE products SET filament_grams = 42, production_minutes = 90 WHERE id = $1', [pid]);

    const res = await run(getPartsCosting, mockReq({}));
    const peca = res.body.find((p: any) => p.id === pid);
    expect(peca.usando_filamento_padrao).toBe(true);
    expect(peca.usando_impressora_padrao).toBe(true);
    expect(Number(peca.custo)).toBeCloseTo(8.3854, 2);
    expect(Number(peca.preco_venda)).toBeCloseTo(17.113, 2);
    expect(Number(peca.margem_real)).toBeCloseTo(45, 1);
  });

  it('relatório financeiro soma custo/faturamento/lucro reais das produções', async () => {
    await seedCostBase();
    const pid = await seedProduct(pool, { onHand: 0, is3d: true, name: 'Talisca' });
    await pool.query('UPDATE products SET filament_grams = 42, production_minutes = 90 WHERE id = $1', [pid]);
    await run(createProduction, mockReq({ body: { partId: pid, quantity: 10, totalMinutes: 900, filamentGrams: 420, date: '2026-02-01T12:00:00Z' } }));

    const res = await run(getFinancialReport, mockReq({ query: {} }));
    const t = res.body.totais;
    expect(t.unidades).toBe(10);
    expect(t.faturamento).toBeCloseTo(171.13, 1);
    expect(t.custo).toBeCloseTo(83.854, 1);
    expect(t.margem).toBeCloseTo(45, 1);
    expect(res.body.ranking[0].name).toBe('Talisca');
  });
});
