import { Request, Response } from 'express';
import { pool } from '../db';
import { setStockAudit } from '../utils/stockAudit';
import { createLog } from '../utils/logger';
import { getClientIp } from '../utils/ip';

// ==========================================
// 1. CATÁLOGO DE PEÇAS 3D (Lê da tabela Products)
// ==========================================
export const get3DParts = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
        SELECT id, sku, name, image_url as image, production_minutes, filament_grams, description 
        FROM products 
        WHERE is_3d = true 
        ORDER BY name ASC
    `);
    
    const formatted = rows.map(r => ({
       id: r.id, 
       code: r.sku || 'S/N', 
       name: r.name, 
       image: r.image, 
       productionMinutes: r.production_minutes || 0, 
       filamentGrams: r.filament_grams || 0, 
       material: 'Padrão', 
       description: r.description
    }));
    
    res.json(formatted);
  } catch (error) {
    console.error("Erro detalhado no get3DParts:", error);
    res.status(500).json({ error: 'Erro ao buscar catálogo 3D' });
  }
};

export const update3DPartDetails = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { productionMinutes, filamentGrams, image, description } = req.body;
  try {
    await pool.query(
      `UPDATE products 
       SET production_minutes = $1, filament_grams = $2, image_url = $3, description = $4 
       WHERE id = $5`,
      [productionMinutes, filamentGrams, image, description, id]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Erro ao atualizar detalhes 3D da peça' });
  }
};

// ==========================================
// 2. DEMANDAS KANBAN (Conectado às Solicitações)
// ==========================================
export const getDemands = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
        SELECT d.id, d.product_id as "partId", d.request_id as "requestId", d.quantity, 
               d.op_number as "opNumber", d.priority, d.status, d.notes, d.created_at as "createdAt",
               p.name as requester
        FROM demands_3d d
        LEFT JOIN requests r ON d.request_id = r.id
        LEFT JOIN profiles p ON r.requester_id = p.id
        ORDER BY d.created_at DESC
    `);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar demandas 3D' });
  }
};

export const updateDemandStatus = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { status } = req.body;
  const userId = (req as any).user?.id || null;
  const client = await pool.connect();

  let deliveredRequestId: string | null = null; // p/ avisar o front após o commit

  try {
    await client.query('BEGIN');

    // 🔒 Lê o status anterior com lock: o crédito de estoque só acontece na
    // TRANSIÇÃO para 'Concluída' (e é revertido ao sair dela). Antes, arrastar o
    // cartão para fora e de volta creditava o estoque em dobro a cada passagem.
    const demandRes = await client.query('SELECT request_id, quantity, product_id, status FROM demands_3d WHERE id = $1 FOR UPDATE', [id]);
    if (demandRes.rows.length === 0) throw new Error('Demanda não encontrada.');
    const demand = demandRes.rows[0];
    const oldStatus = demand.status;

    // SKU para identificar o produto nos logs de auditoria (legibilidade)
    let demandSku: string | null = null;
    if (demand.product_id) {
      const skuRes = await client.query('SELECT sku FROM products WHERE id = $1', [demand.product_id]);
      demandSku = skuRes.rows[0]?.sku || null;
    }

    await setStockAudit(
      client,
      status === 'Concluída' ? 'PRODUCAO_3D_ENTRADA' : 'PRODUCAO_3D_ESTORNO',
      userId,
      `demanda_3d:${id}`
    );

    await client.query('UPDATE demands_3d SET status = $1 WHERE id = $2', [status, id]);

    if (status === 'Concluída' && oldStatus !== 'Concluída') {
        // Verifica se a solicitação de origem ainda está viva: se sim, o produzido
        // entra reservado para ela; se não (entregue/rejeitada), entra como estoque
        // livre — antes a reserva ficava presa para sempre.
        let requestAlive = false;
        if (demand.request_id) {
            const reqCheck = await client.query('SELECT status FROM requests WHERE id = $1', [demand.request_id]);
            requestAlive = ['aberto', 'aprovado'].includes(reqCheck.rows[0]?.status);
        }

        // 1️⃣ ENTRADA FÍSICA do que foi produzido (demand.quantity = a produzir).
        //    Quando não há nada a produzir (demand.quantity = 0) isto é um no-op.
        //    IDEMPOTÊNCIA: se já existe uma produção registada para esta demanda
        //    (operador usou a página "Registrar Produção"), o estoque já foi
        //    creditado lá — não credita de novo (evita conflito de estoque em
        //    dobro entre o Quadro de Demandas e a página de Produção).
        if (demand.product_id && Number(demand.quantity) > 0) {
            const existingProd = await client.query('SELECT 1 FROM productions_3d WHERE demand_id = $1 LIMIT 1', [id]);

            if (existingProd.rows.length === 0) {
                await client.query(
                    `INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved)
                     VALUES ($1, $2, $3)
                     ON CONFLICT (product_id)
                     DO UPDATE SET quantity_on_hand = COALESCE(stock.quantity_on_hand, 0) + $2,
                                   quantity_reserved = COALESCE(stock.quantity_reserved, 0) + $3`,
                    [demand.product_id, demand.quantity, requestAlive ? demand.quantity : 0]
                );

                // Registra a produção para aparecer no Histórico de Produção e nas
                // métricas do Dashboard 3D — antes, finalizar pelo Quadro creditava
                // estoque mas NÃO registava a produção (ficava invisível no painel).
                const partInfo = await client.query('SELECT production_minutes, filament_grams FROM products WHERE id = $1', [demand.product_id]);
                const totalMinutes = Number(partInfo.rows[0]?.production_minutes || 0) * Number(demand.quantity);
                const filamentGrams = Number(partInfo.rows[0]?.filament_grams || 0) * Number(demand.quantity);
                await client.query(
                    `INSERT INTO productions_3d (product_id, demand_id, quantity, operator_id, total_minutes, filament_grams, date)
                     VALUES ($1, $2, $3, $4, $5, $6, NOW())`,
                    [demand.product_id, id, demand.quantity, userId, totalMinutes, filamentGrams]
                );

                await client.query(
                    `INSERT INTO audit_logs (user_id, action, details)
                     VALUES ($1, $2, $3)`,
                    [userId, 'ENTRADA_ESTOQUE_3D', JSON.stringify({ produto: demandSku || demand.product_id, quantidade: demand.quantity, motivo: 'Produção 3D Concluída' })]
                );
            }
        }

        // 2️⃣ BAIXA AUTOMÁTICA NA SOLICITAÇÃO: quando o operador 3D conclui a
        //    ÚLTIMA demanda de um pedido 100% 3D, o próprio ato de finalizar já
        //    entrega o pedido (debita o físico, libera a reserva) — o almoxarife
        //    não precisa fazer nada. Antes, concluir só creditava estoque e
        //    deixava o pedido em aberto ("somente fazendo entrada").
        if (requestAlive && demand.request_id) {
            const reqLock = await client.query('SELECT status FROM requests WHERE id = $1 FOR UPDATE', [demand.request_id]);
            const reqStatus = reqLock.rows[0]?.status;

            if (reqStatus === 'aberto' || reqStatus === 'aprovado') {
                const pending = await client.query(
                    `SELECT COUNT(*)::int AS n FROM demands_3d
                     WHERE request_id = $1 AND status NOT IN ('Concluída', 'Cancelada', 'Rejeitada')`,
                    [demand.request_id]
                );
                const itemsRes = await client.query(
                    `SELECT ri.id, ri.product_id, ri.quantity_requested, ri.quantity_delivered, p.is_3d
                     FROM request_items ri LEFT JOIN products p ON ri.product_id = p.id
                     WHERE ri.request_id = $1`,
                    [demand.request_id]
                );
                const allItems3D = itemsRes.rows.length > 0 &&
                    itemsRes.rows.every((it: any) => it.product_id && it.is_3d);

                if (pending.rows[0].n === 0 && allItems3D) {
                    // Contexto de auditoria da baixa (o débito é uma ENTREGA, não uma entrada)
                    await setStockAudit(client, 'SOLICITACAO_ENTREGA', userId, `solicitacao:${demand.request_id}`);

                    for (const it of itemsRes.rows) {
                        const finalQty = parseFloat(it.quantity_delivered ?? it.quantity_requested);
                        // Reserva a liberar = porção realmente reservada (prateleira +
                        // produzido), i.e. pedido menos o que ainda estaria no Kanban.
                        const pend = await client.query(
                            `SELECT COALESCE(SUM(quantity), 0) AS pending FROM demands_3d
                             WHERE request_id = $1 AND product_id = $2 AND status NOT IN ('Concluída', 'Cancelada', 'Rejeitada')`,
                            [demand.request_id, it.product_id]
                        );
                        const reserveRelease = Math.max(0, parseFloat(it.quantity_requested) - parseFloat(pend.rows[0].pending));

                        const stockCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1 FOR UPDATE', [it.product_id]);
                        if (parseFloat(stockCheck.rows[0]?.quantity_on_hand || 0) < finalQty) {
                            throw new Error('Furo de estoque ao dar baixa automática na solicitação 3D.');
                        }
                        await client.query(
                            `UPDATE stock
                             SET quantity_on_hand = quantity_on_hand - $1,
                                 quantity_reserved = GREATEST(0, quantity_reserved - $2)
                             WHERE product_id = $3`,
                            [finalQty, reserveRelease, it.product_id]
                        );
                        await client.query('UPDATE request_items SET quantity_delivered = $1 WHERE id = $2', [finalQty, it.id]);
                    }

                    await client.query(`UPDATE requests SET status = 'entregue' WHERE id = $1`, [demand.request_id]);
                    await createLog(userId, 'ENTREGAR_SOLICITACAO', {
                        changes: { id_solicitacao: { new: demand.request_id }, status: { old: reqStatus, new: 'entregue' }, origem: { new: 'Baixa automática pela Produção 3D' } }
                    }, getClientIp(req), client);
                    deliveredRequestId = demand.request_id;
                } else {
                    // Ainda há itens não-3D ou outras demandas pendentes: o pedido
                    // fica com o almoxarife (reabre p/ 'aprovado' se estava 'aberto').
                    await client.query(`UPDATE requests SET status = 'aprovado' WHERE id = $1 AND status = 'aberto'`, [demand.request_id]);
                }
            }
        }
    } else if (oldStatus === 'Concluída' && status !== 'Concluída') {
        // Saiu de 'Concluída': desfaz o crédito para manter a simetria.
        // Se a solicitação já recebeu baixa (entregue), reabrir corromperia o
        // estoque — bloqueia com mensagem clara.
        if (demand.request_id) {
            const reqCheck = await client.query('SELECT status FROM requests WHERE id = $1', [demand.request_id]);
            if (reqCheck.rows[0]?.status === 'entregue') {
                throw new Error('Não é possível reabrir: a solicitação já recebeu baixa (entregue).');
            }
        }
        // Só devolve a reserva se o pedido de origem ainda estiver vivo (mesmo
        // critério do crédito) para não roubar reserva de outros pedidos.
        if (demand.product_id && Number(demand.quantity) > 0) {
            let requestAlive = false;
            if (demand.request_id) {
                const reqCheck = await client.query('SELECT status FROM requests WHERE id = $1', [demand.request_id]);
                requestAlive = ['aberto', 'aprovado'].includes(reqCheck.rows[0]?.status);
            }
            await client.query(
                `UPDATE stock
                 SET quantity_on_hand = GREATEST(0, COALESCE(quantity_on_hand, 0) - $1),
                     quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $2)
                 WHERE product_id = $3`,
                [demand.quantity, requestAlive ? demand.quantity : 0, demand.product_id]
            );
            await client.query(
                `INSERT INTO audit_logs (user_id, action, details)
                 VALUES ($1, $2, $3)`,
                [userId, 'SAIDA_ESTOQUE_3D', JSON.stringify({ produto: demandSku || demand.product_id, quantidade: demand.quantity, motivo: 'Demanda 3D reaberta (crédito revertido)' })]
            );
        }
    }

    await client.query('COMMIT');

    // 🔔 Avisa o front em tempo real: estoque mudou e (se houve baixa) o pedido foi entregue
    if ((req as any).io) {
        if (demand.product_id) (req as any).io.emit('stock_updated', { changedProducts: [demand.product_id] });
        if (deliveredRequestId) (req as any).io.emit('request_updated', { id: deliveredRequestId, status: 'entregue' });
    }

    res.json({ success: true, delivered: !!deliveredRequestId });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message || 'Erro ao mover demanda no Kanban' });
  } finally {
    client.release();
  }
};

// ==========================================
// 3. HISTÓRICO E REGISTO DE PRODUÇÃO (COM ESTOQUE AUTOMÁTICO)
// ==========================================

export const getProductions = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT p3d.id, p3d.product_id as "partId", p3d.demand_id as "demandId", p3d.quantity, 
             p3d.total_minutes as "totalMinutes", p3d.filament_grams as "filamentGrams", 
             p3d.date, pr.name as operator 
      FROM productions_3d p3d
      LEFT JOIN profiles pr ON p3d.operator_id = pr.id
      ORDER BY p3d.date ASC
    `);
    res.json(rows);
  } catch (error) {
    console.error('Erro ao buscar produções:', error);
    res.status(500).json({ error: 'Erro ao buscar produções' });
  }
};

export const createProduction = async (req: Request, res: Response) => {
  const { partId, demandId, quantity, totalMinutes, filamentGrams, date } = req.body;
  const operatorId = (req as any).user?.id || null; 
  
  const client = await pool.connect();

  try {
    const numericQty = Number(quantity);
    if (!partId || isNaN(numericQty) || numericQty <= 0) {
      return res.status(400).json({ error: 'Produção inválida: informe a peça e uma quantidade maior que zero.' });
    }

    await client.query('BEGIN'); // Inicia a transação

    // 🛡️ Anti-conflito de estoque: se esta produção está vinculada a uma demanda
    // que JÁ foi finalizada no Quadro (Concluída), o estoque já foi creditado por
    // aquela finalização — registar de novo aqui creditaria em dobro. Bloqueia.
    if (demandId) {
      const demChk = await client.query('SELECT status FROM demands_3d WHERE id = $1', [demandId]);
      if (demChk.rows[0]?.status === 'Concluída') {
        await client.query('ROLLBACK');
        return res.status(409).json({ error: 'Esta demanda já foi finalizada no Quadro de Demandas — a produção e a entrada de estoque já foram registadas.' });
      }
    }

    await setStockAudit(client, 'PRODUCAO_3D_ENTRADA', operatorId, demandId ? `demanda_3d:${demandId}` : 'producao_3d:livre');

    // 1. REGISTAR A PRODUÇÃO
    const prodRes = await client.query(`
        INSERT INTO productions_3d 
        (product_id, demand_id, quantity, operator_id, total_minutes, filament_grams, date)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, product_id as "partId", demand_id as "demandId", quantity, 
                  total_minutes as "totalMinutes", filament_grams as "filamentGrams", 
                  date, operator_id as operator
    `, [partId, demandId || null, quantity, operatorId, totalMinutes, filamentGrams, date]);
    
    // 2. DAR ENTRADA NO ESTOQUE FÍSICO
    await client.query(`
        INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved)
        VALUES ($1, $2, 0)
        ON CONFLICT (product_id) 
        DO UPDATE SET quantity_on_hand = COALESCE(stock.quantity_on_hand, 0) + $2
    `, [partId, quantity]);

    // 3. REGISTAR O HISTÓRICO DE MOVIMENTAÇÃO (Tabela de Auditoria do seu Sistema)
    const skuRes = await client.query('SELECT sku FROM products WHERE id = $1', [partId]);
    const reason = demandId ? 'Produção 3D (Demanda Kanban)' : 'Produção 3D (Estoque Livre)';
    await client.query(`
        INSERT INTO audit_logs (user_id, action, details)
        VALUES ($1, $2, $3)
    `, [operatorId, 'ENTRADA_ESTOQUE_3D', JSON.stringify({ produto: skuRes.rows[0]?.sku || partId, quantidade: quantity, motivo: reason })]);

    await client.query('COMMIT'); // Guarda tudo!
    res.status(201).json(prodRes.rows[0]);
    
  } catch (error) {
    await client.query('ROLLBACK'); // Em caso de erro, cancela tudo
    console.error('Erro ao criar produção e dar entrada no estoque:', error);
    res.status(500).json({ error: 'Erro ao registar produção 3D' });
  } finally {
    client.release();
  }
};

export const deleteProduction = async (req: Request, res: Response) => {
  const { id } = req.params;
  const operatorId = (req as any).user?.id || null; 
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Descobrir qual era a peça e a quantidade
    const prodRes = await client.query('SELECT product_id, quantity FROM productions_3d WHERE id = $1', [id]);
    if (prodRes.rows.length === 0) throw new Error("Produção não encontrada");
    const { product_id, quantity } = prodRes.rows[0];

    await setStockAudit(client, 'PRODUCAO_3D_ESTORNO', operatorId, `producao_3d:${id}`);

    // 2. Apagar a produção
    await client.query('DELETE FROM productions_3d WHERE id = $1', [id]);

    // 3. Subtrair do estoque
    await client.query(`
        UPDATE stock 
        SET quantity_on_hand = GREATEST(COALESCE(quantity_on_hand, 0) - $2, 0)
        WHERE product_id = $1
    `, [product_id, quantity]);

    // 4. Registar no histórico (Auditoria)
    const skuRes = await client.query('SELECT sku FROM products WHERE id = $1', [product_id]);
    await client.query(`
        INSERT INTO audit_logs (user_id, action, details)
        VALUES ($1, $2, $3)
    `, [operatorId, 'SAIDA_ESTOQUE_3D', JSON.stringify({ produto: skuRes.rows[0]?.sku || product_id, quantidade: quantity, motivo: 'Correção: Apagou registo de Produção 3D' })]);

    await client.query('COMMIT');
    res.json({ success: true });
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Erro ao apagar produção e reverter estoque:', error);
    res.status(500).json({ error: 'Erro ao apagar produção 3D' });
  } finally {
    client.release();
  }
};
