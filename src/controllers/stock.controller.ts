import { Request, Response } from 'express';
import { pool } from '../db';
import { createLog } from '../utils/logger';
import { getClientIp } from '../utils/ip';
import { sendPushNotificationToRole } from '../utils/notifications';
import { validatePositiveItems } from '../middlewares/validators';

export const getStock = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, json_build_object('id', p.id, 'name', p.name, 'sku', p.sku, 'unit', p.unit, 'min_stock', p.min_stock, 'unit_price', p.unit_price, 'sales_price', p.sales_price, 'tags', p.tags) as products
      FROM stock s JOIN products p ON s.product_id = p.id WHERE p.active = true ORDER BY s.created_at DESC;
    `);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar estoque' }); }
};

export const getStockReservations = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const stockCheck = await pool.query('SELECT product_id FROM stock WHERE id = $1', [id]);
    if (stockCheck.rows.length === 0) return res.status(404).json({ error: 'Estoque não encontrado' });
    const productId = stockCheck.rows[0].product_id;

    let reservations: any[] = [];
    const reqRes = await pool.query(`SELECT r.id as request_id, COALESCE(pf.sector, r.sector) as sector, ri.quantity_requested as quantity FROM request_items ri JOIN requests r ON ri.request_id = r.id LEFT JOIN profiles pf ON r.requester_id = pf.id WHERE ri.product_id = $1 AND r.status IN ('aberto', 'aprovado') AND ri.quantity_requested > 0`, [productId]);
    const travelRes = await pool.query(`SELECT t.id as request_id, 'Viagem: ' || t.city as sector, ti.quantity_out as quantity FROM travel_order_items ti JOIN travel_orders t ON ti.travel_order_id = t.id WHERE ti.product_id = $1 AND t.status IN ('pending', 'awaiting_stock') AND ti.quantity_out > 0`, [productId]);
    const sepRes = await pool.query(`SELECT s.id as request_id, 'Separação OP: ' || s.client_name as sector, si.quantity as quantity FROM separation_items si JOIN separations s ON si.separation_id = s.id WHERE si.product_id = $1 AND s.status = 'em_separacao' AND si.quantity > 0`, [productId]);
    const repRes = await pool.query(`SELECT rep.id as request_id, 'Reposição: ' || rep.client_name as sector, ri.quantity as quantity FROM replenishment_items ri JOIN replenishments rep ON ri.replenishment_id = rep.id WHERE ri.product_id = $1 AND rep.status = 'em_preparo' AND ri.quantity > 0`, [productId]);

    reservations.push(...reqRes.rows, ...travelRes.rows, ...sepRes.rows, ...repRes.rows);
    res.json(reservations);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar reservas vinculadas' }); }
};

export const updateStock = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  const { quantity_on_hand, quantity_reserved } = req.body;
  try {
    const userCheck = await pool.query('SELECT role, sector FROM profiles WHERE id = $1', [userId]);
    const isMaster = userCheck.rows[0].role === 'admin' || userCheck.rows[0].role === 'almoxarife';
    
    if (!isMaster) {
       const stockItem = await pool.query(`SELECT p.tags FROM stock s JOIN products p ON s.product_id = p.id WHERE s.id = $1`, [id]);
       const hasTag = Array.isArray(stockItem.rows[0]?.tags) && stockItem.rows[0].tags.some((t: string) => t.toLowerCase() === 'usinagem');
       if (userCheck.rows[0].sector?.toLowerCase() !== 'usinagem' || !hasTag) return res.status(403).json({ error: 'Sem permissão.' });
    }

    const oldStock = await pool.query('SELECT quantity_on_hand, quantity_reserved, product_id FROM stock WHERE id = $1', [id]);
    
    // 🛡️ CORREÇÃO TYPESCRIPT APLICADA:
    let fields: string[] = []; 
    let values: any[] = []; 
    let index = 1;
    
    if (quantity_on_hand !== undefined) { fields.push(`quantity_on_hand = $${index++}`); values.push(quantity_on_hand); }
    if (quantity_reserved !== undefined) { fields.push(`quantity_reserved = $${index++}`); values.push(quantity_reserved); }
    
    if (fields.length > 0) {
      values.push(id);
      await pool.query(`UPDATE stock SET ${fields.join(', ')} WHERE id = $${index}`, values);
      if (oldStock.rows.length > 0) {
         await createLog(userId, 'UPDATE_STOCK', { stock_id: id, old_qty: oldStock.rows[0].quantity_on_hand, new_qty: quantity_on_hand }, getClientIp(req));
      }
    }
    res.json({ success: true });
  } catch (error: any) { res.status(500).json({ error: 'Erro ao ajustar estoque' }); }
};

export const manualEntry = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { items } = req.body;
  const client = await pool.connect();
  try {
    validatePositiveItems(items);
    await client.query('BEGIN');
    const logRes = await client.query("INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", [`Entrada Manual - ${new Date().toLocaleDateString('pt-BR')}`, true, items.length]);
    for (const item of items) {
      if (!item.product_id || !item.quantity) throw new Error("Item inválido.");
      await client.query("INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", [logRes.rows[0].id, item.product_id, item.quantity]);
      await client.query("UPDATE stock SET quantity_on_hand = COALESCE(quantity_on_hand, 0) + $1 WHERE product_id = $2", [item.quantity, item.product_id]);
    }
    await createLog(userId, 'MANUAL_ENTRY', { itemCount: items.length }, getClientIp(req), client);
    await client.query('COMMIT');
    
    if ((req as any).io) (req as any).io.to('compras').emit('new_request_notification', { message: '📦 Nova entrada registrada!', action: 'Ver Estoque', type: 'entrada' });
    sendPushNotificationToRole('compras', 'Nova Entrada de Estoque', 'O Almoxarifado registrou uma entrada.', '/stock');
    res.status(201).json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
};

export const manualWithdrawal = async (req: Request, res: Response) => {
  const { sector, items } = req.body;
  const userId = (req as any).user.id;
  const client = await pool.connect();
  try {
    validatePositiveItems(items);
    await client.query('BEGIN');
    const sepRes = await client.query('INSERT INTO separations (destination, status, type) VALUES ($1, $2, $3) RETURNING id', [sector, 'concluida', 'manual']);
    for (const item of items) {
      if (!item.product_id || !item.quantity) throw new Error("Item inválido.");
      const stCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1 FOR UPDATE', [item.product_id]);
      if(parseFloat(stCheck.rows[0]?.quantity_on_hand || 0) < item.quantity) throw new Error(`Estoque insuficiente ID ${item.product_id}.`);
      await client.query('INSERT INTO separation_items (separation_id, product_id, quantity, observation) VALUES ($1, $2, $3, $4)', [sepRes.rows[0].id, item.product_id, item.quantity, item.observation || null]);
      await client.query('UPDATE stock SET quantity_on_hand = quantity_on_hand - $1 WHERE product_id = $2', [item.quantity, item.product_id]);
    }
    await createLog(userId, 'MANUAL_WITHDRAWAL', { separationId: sepRes.rows[0].id, sector }, getClientIp(req), client);
    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
};
