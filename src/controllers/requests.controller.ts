import { Request, Response } from 'express';
import { pool } from '../db';
import { createLog } from '../utils/logger';
import { getClientIp } from '../utils/ip';
import { sendPushNotificationToRole } from '../utils/notifications';
import { validatePositiveItems } from '../middlewares/validators';

export const getRequests = async (req: Request, res: Response) => {
  try {
    const query = `
      WITH FilteredRequests AS (
          SELECT * FROM requests 
          WHERE status IN ('aberto', 'aprovado') OR created_at >= NOW() - INTERVAL '30 days'
          ORDER BY created_at DESC LIMIT 200
      )
      SELECT r.*, json_build_object('name', p.name, 'sector', p.sector) as requester,
          COALESCE(ri_agg.items, '[]'::json) as request_items
      FROM FilteredRequests r
      LEFT JOIN profiles p ON r.requester_id = p.id
      LEFT JOIN (
          SELECT ri.request_id, json_agg(
              json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'custom_product_name', ri.custom_product_name, 'observation', ri.observation, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit, 'tags', pr.tags) ELSE NULL END)
          ) as items
          FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id
          WHERE ri.request_id IN (SELECT id FROM FilteredRequests) GROUP BY ri.request_id
      ) ri_agg ON ri_agg.request_id = r.id ORDER BY r.created_at DESC;
    `;
    const { rows } = await pool.query(query);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar solicitações' }); }
};

export const getMyRequests = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  try {
    const query = `
      WITH FilteredRequests AS (
          SELECT * FROM requests 
          WHERE requester_id = $1 AND (status IN ('aberto', 'aprovado') OR created_at >= NOW() - INTERVAL '30 days')
          ORDER BY created_at DESC LIMIT 200
      )
      SELECT r.*, COALESCE(ri_agg.items, '[]'::json) as request_items
      FROM FilteredRequests r
      LEFT JOIN (
          SELECT ri.request_id, json_agg(
              json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'custom_product_name', ri.custom_product_name, 'observation', ri.observation, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit, 'tags', pr.tags) ELSE NULL END)
          ) as items
          FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id
          WHERE ri.request_id IN (SELECT id FROM FilteredRequests) GROUP BY ri.request_id
      ) ri_agg ON ri_agg.request_id = r.id ORDER BY r.created_at DESC;
    `;
    const { rows } = await pool.query(query, [userId]);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar minhas solicitações' }); }
};

export const createRequest = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { sector, items } = req.body;
  const client = await pool.connect();
  try {
    validatePositiveItems(items);
    await client.query('BEGIN');
    const reqRes = await client.query('INSERT INTO requests (requester_id, sector, status) VALUES ($1, $2, $3) RETURNING id', [userId, sector, 'aberto']);
    const requestId = reqRes.rows[0].id;
    const sortedItems = [...items].sort((a, b) => {
       if (!a.product_id) return 1; if (!b.product_id) return -1;
       return String(a.product_id).localeCompare(String(b.product_id));
    });

    for (const item of sortedItems) {
      const isCustom = item.product_id === 'custom' || !item.product_id;
      const productId = isCustom ? null : item.product_id;
      const customName = isCustom ? item.custom_name : null;
      if (productId) {
        const stockCheck = await client.query('SELECT (quantity_on_hand - quantity_reserved) as available FROM stock WHERE product_id = $1 FOR UPDATE', [productId]);
        const available = parseFloat(stockCheck.rows[0]?.available || 0);
        if (available < item.quantity) throw new Error(`Estoque disponível insuficiente para o produto ID: ${productId}`);
        await client.query(`UPDATE stock SET quantity_reserved = COALESCE(quantity_reserved, 0) + $1 WHERE product_id = $2`, [item.quantity, productId]);
      }
      await client.query('INSERT INTO request_items (request_id, product_id, custom_product_name, quantity_requested, observation) VALUES ($1, $2, $3, $4, $5)', [requestId, productId, customName, item.quantity, item.observation || null]);
    }
    
    await createLog(userId, 'CREATE_REQUEST', { requestId, sector, itemCount: items.length }, getClientIp(req), client);
    await client.query('COMMIT');

    const fullReqQuery = `SELECT r.*, json_build_object('name', p.name, 'sector', p.sector) as requester, (SELECT COALESCE(json_agg(json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'custom_product_name', ri.custom_product_name, 'observation', ri.observation, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit, 'tags', pr.tags) ELSE NULL END)), '[]'::json) FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id WHERE ri.request_id = r.id) as request_items FROM requests r LEFT JOIN profiles p ON r.requester_id = p.id WHERE r.id = $1`;
    const { rows: fullReqRows } = await client.query(fullReqQuery, [requestId]);
    
    if ((req as any).io) {
        const notificationData = { id: `req-${requestId}-${Date.now()}`, message: `📢 Nova solicitação do setor: ${sector}`, action: 'Ver Pedidos', type: 'solicitacao' };
        (req as any).io.to(['almoxarife', 'admin', 'escritorio']).emit('new_request_notification', notificationData);
        (req as any).io.to(['almoxarife', 'admin', 'escritorio']).emit('new_request', fullReqRows[0]);
        (req as any).io.emit('refresh_stock'); 
    }
    sendPushNotificationToRole('almoxarife', 'Nova Solicitação!', `O setor ${sector} fez um novo pedido.`, '/requests');
    res.status(201).json({ success: true, id: requestId });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(error.message.includes('Estoque disponível insuficiente') ? 400 : 500).json({ error: `Erro Técnico: ${error.message}` }); 
  } finally { client.release(); }
};

export const updateRequestStatus = async (req: Request, res: Response) => {
  const { id } = req.params;
  const userId = (req as any).user.id;
  const { status, rejection_reason } = req.body;
  const client = await pool.connect();
  try {
    const userCheck = await pool.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') return res.status(403).json({ error: 'Sem permissão.' });

    await client.query('BEGIN');
    const currentRes = await client.query('SELECT status FROM requests WHERE id = $1 FOR UPDATE', [id]);
    if (!currentRes.rows[0]?.status) throw new Error("Solicitação não encontrada");
    const currentStatus = currentRes.rows[0].status;

    const itemsRes = await client.query('SELECT product_id, quantity_requested FROM request_items WHERE request_id = $1 ORDER BY product_id', [id]);
    
    if (status === 'entregue' && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
      for (const item of itemsRes.rows) {
        if (item.product_id) {
          const stockCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1 FOR UPDATE', [item.product_id]);
          if (parseFloat(stockCheck.rows[0]?.quantity_on_hand || 0) < item.quantity_requested) throw new Error(`Furo de Estoque no produto ID ${item.product_id}.`);
          await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand - $1, quantity_reserved = GREATEST(0, quantity_reserved - $1) WHERE product_id = $2`, [item.quantity_requested, item.product_id]);
        }
      }
    } else if (status === 'rejeitado' && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
      for (const item of itemsRes.rows) {
        if (item.product_id) await client.query(`UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1) WHERE product_id = $2`, [item.quantity_requested, item.product_id]);
      }
    }

    await client.query('UPDATE requests SET status = $1, rejection_reason = $2 WHERE id = $3', [status, rejection_reason || null, id]);
    await createLog(userId, status === 'entregue' ? 'APPROVE_REQUEST' : status === 'rejeitado' ? 'REJECT_REQUEST' : 'UPDATE_REQUEST_STATUS', { requestId: id, newStatus: status, reason: rejection_reason }, getClientIp(req), client);
    await client.query('COMMIT');

    if ((req as any).io) { (req as any).io.emit('refresh_requests'); (req as any).io.emit('refresh_stock'); }
    res.json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message || 'Erro ao atualizar status' });
  } finally { client.release(); }
};

export const deleteRequest = async (req: Request, res: Response) => {
  const { id } = req.params;
  const userId = (req as any).user.id;
  const client = await pool.connect();
  try {
    const userCheck = await pool.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') return res.status(403).json({ error: 'Sem permissão.' });

    await client.query('BEGIN');
    const reqRes = await client.query('SELECT status FROM requests WHERE id = $1 FOR UPDATE', [id]);
    if (reqRes.rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Não encontrada.' }); }
    const { status } = reqRes.rows[0];

    if (status === 'rejeitado' || status === 'entregue') throw new Error('Não é possível cancelar.');
    if (status === 'aberto' || status === 'aprovado') {
       const itemsRes = await client.query('SELECT product_id, quantity_requested FROM request_items WHERE request_id = $1', [id]);
       for (const item of itemsRes.rows) {
         if (item.product_id) await client.query(`UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1) WHERE product_id = $2`, [item.quantity_requested, item.product_id]);
       }
    }

    await client.query("UPDATE requests SET status = 'rejeitado', rejection_reason = 'Cancelado pelo usuário/sistema' WHERE id = $1", [id]);
    await createLog(userId, 'CANCEL_REQUEST', { requestId: id, previousStatus: status }, getClientIp(req), client);
    await client.query('COMMIT');
    
    if ((req as any).io) { (req as any).io.emit('refresh_requests'); (req as any).io.emit('refresh_stock'); }
    res.json({ success: true, message: 'Pedido cancelado.' });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
};