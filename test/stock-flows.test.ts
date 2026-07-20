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
import { createProduction, updateDemandStatus } from '../src/controllers/producao3d.controller';
import { createReplenishment, authorizeReplenishment } from '../src/controllers/replenishments.controller';
import { createTravelOrder, reconcileTravelOrder } from '../src/controllers/travels.controller';

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
