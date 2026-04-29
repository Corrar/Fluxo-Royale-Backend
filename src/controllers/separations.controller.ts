import { Request, Response } from 'express';
import { pool } from '../db';
import { createLog } from '../utils/logger';
import { getClientIp } from '../utils/ip';
import { validatePositiveItems } from '../middlewares/validators';

export const getSeparations = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*,
        (SELECT json_agg(json_build_object('id', si.id, 'product_id', si.product_id, 'quantity', si.quantity, 'qty_requested', si.qty_requested, 'observation', si.observation, 'products', json_build_object('name', p.name, 'sku', p.sku, 'unit', p.unit, 'unit_price', p.unit_price, 'stock', json_build_object('quantity_on_hand', COALESCE(st.quantity_on_hand, 0), 'quantity_reserved', COALESCE(st.quantity_reserved, 0)))))
         FROM separation_items si JOIN products p ON si.product_id = p.id LEFT JOIN stock st ON p.id = st.product_id WHERE si.separation_id = s.id) as items,
        (SELECT json_agg(json_build_object('id', sr.id, 'product_id', sr.product_id, 'quantity', sr.quantity, 'status', sr.status, 'product_name', p.name)) FROM separation_returns sr JOIN products p ON sr.product_id = p.id WHERE sr.separation_id = s.id) as returns
      FROM separations s ORDER BY s.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar separações' }); }
};

export const createSeparation = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  // 🟢 CORREÇÃO: Adicionado o recebimento do client_service_id do frontend
  const { client_name, production_order, destination, items, client_service_id } = req.body;
  const client = await pool.connect();
  try {
    validatePositiveItems(items);
    await client.query('BEGIN');
    const userCheck = await client.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') throw new Error('Sem permissão.');

    // 🟢 CORREÇÃO: Guardamos o client_service_id oficialmente na base de dados
    const sepRes = await client.query(
      `INSERT INTO separations (destination, client_name, production_order, status, type, client_service_id) VALUES ($1, $2, $3, 'pendente', 'op', $4) RETURNING id`, 
      [destination, client_name, production_order, client_service_id || null]
    );
    
    for (const item of items) {
      await client.query(`INSERT INTO separation_items (separation_id, product_id, qty_requested, quantity, observation) VALUES ($1, $2, $3, 0, $4)`, [sepRes.rows[0].id, item.product_id, item.quantity, item.observation || null]);
    }
    
    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'CRIAR_SEPARACAO', { id_separacao: sepRes.rows[0].id, cliente: client_name }, getClientIp(req), client);
    await client.query('COMMIT');
    if ((req as any).io) (req as any).io.emit('separations_update');
    res.status(201).json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(400).json({ error: error.message });
  } finally { client.release(); }
};

export const authorizeSeparation = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { items, action } = req.body; 
  const userId = (req as any).user.id;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const userCheck = await client.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') throw new Error('Acesso negado.');

    for (const item of items) {
      const oldItem = await client.query('SELECT quantity, product_id FROM separation_items WHERE id = $1', [item.id]);
      if (oldItem.rows.length > 0) {
        const oldQty = parseFloat(oldItem.rows[0].quantity || 0);
        const newQty = parseFloat(item.quantity);
        if (isNaN(newQty) || newQty < 0) throw new Error("Quantidade inválida.");

        const productId = oldItem.rows[0].product_id;
        const diff = newQty - oldQty;
        await client.query('UPDATE separation_items SET quantity = $1 WHERE id = $2', [newQty, item.id]);

        if (action === 'reservar') {
          if (diff > 0) {
            const st = await client.query('SELECT (quantity_on_hand - quantity_reserved) as available FROM stock WHERE product_id = $1 FOR UPDATE', [productId]);
            if (parseFloat(st.rows[0]?.available || 0) < diff) throw new Error(`Estoque insuficiente ID ${productId}`);
          }
          await client.query(`UPDATE stock SET quantity_reserved = quantity_reserved + $1 WHERE product_id = $2`, [diff, productId]);
        } else if (action === 'entregar') {
          const stCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1 FOR UPDATE', [productId]);
          if (parseFloat(stCheck.rows[0]?.quantity_on_hand || 0) < newQty) throw new Error(`Furo de Estoque! Saldo menor que a entrega (ID ${productId}).`);
          await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand - $1, quantity_reserved = GREATEST(0, quantity_reserved - $2) WHERE product_id = $3`, [newQty, oldQty, productId]);
        }
      }
    }

    const newStatus = action === 'entregar' ? 'entregue' : 'em_separacao';
    await client.query(`UPDATE separations SET status = $1 ${action === 'entregar' ? ', sent_at = NOW()' : ''} WHERE id = $2`, [newStatus, id]);
    
    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'AUTORIZAR_SEPARACAO', { id_separacao: id, acao: action }, getClientIp(req), client);
    await client.query('COMMIT');
    if ((req as any).io) (req as any).io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(400).json({ error: error.message });
  } finally { client.release(); }
};

export const deleteSeparation = async (req: Request, res: Response) => {
  const { id } = req.params;
  const userId = (req as any).user.id;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userCheck = await client.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') throw new Error('Acesso negado.');

    const sepRes = await client.query('SELECT status FROM separations WHERE id = $1 FOR UPDATE', [id]);
    if(sepRes.rows.length === 0) throw new Error("Pedido não encontrado");
    if(sepRes.rows[0].status === 'entregue' || sepRes.rows[0].status === 'cancelada') throw new Error("Não é possível inativar pedidos concluídos.");

    const itemsRes = await client.query('SELECT product_id, quantity FROM separation_items WHERE separation_id = $1', [id]);
    for (const item of itemsRes.rows) {
       await client.query('UPDATE stock SET quantity_reserved = GREATEST(0, quantity_reserved - $1) WHERE product_id = $2', [item.quantity, item.product_id]);
    }

    await client.query("UPDATE separations SET status = 'cancelada' WHERE id = $1", [id]);
    
    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'CANCELAR_SEPARACAO', { id_separacao: id }, getClientIp(req), client);
    await client.query('COMMIT');
    if ((req as any).io) (req as any).io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) { 
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(400).json({ error: error.message }); 
  } finally { client.release(); }
};

// 🛠️ NOVA FUNÇÃO: Editar Pedido (updateSeparation)
export const updateSeparation = async (req: Request, res: Response) => {
  const { id } = req.params;
  // 🟢 CORREÇÃO: Adicionado o recebimento do client_service_id do frontend
  const { client_name, production_order, destination, items, client_service_id } = req.body;
  const userId = (req as any).user.id;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const userCheck = await client.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') throw new Error('Acesso negado.');

    // 🟢 CORREÇÃO: Atualizamos o client_service_id na base de dados
    await client.query(
      `UPDATE separations SET client_name = $1, production_order = $2, destination = $3, client_service_id = $4 WHERE id = $5`,
      [client_name, production_order, destination, client_service_id || null, id]
    );

    // 2. Compara os itens antigos com os novos
    const existingItemsRes = await client.query('SELECT id, product_id, quantity FROM separation_items WHERE separation_id = $1', [id]);
    const existingItems = existingItemsRes.rows;
    const newProductIds = items.map((i: any) => i.product_id);

    // 3. Remove itens que foram apagados na edição e liberta o stock reservado
    for (const old of existingItems) {
      if (!newProductIds.includes(old.product_id)) {
         if (old.quantity > 0) {
             await client.query('UPDATE stock SET quantity_reserved = GREATEST(0, quantity_reserved - $1) WHERE product_id = $2', [old.quantity, old.product_id]);
         }
         await client.query('DELETE FROM separation_items WHERE id = $1', [old.id]);
      }
    }

    // 4. Adiciona novos itens ou atualiza a quantidade solicitada dos existentes
    for (const item of items) {
      const exists = existingItems.find(old => old.product_id === item.product_id);
      if (exists) {
        await client.query('UPDATE separation_items SET qty_requested = $1 WHERE id = $2', [item.quantity, exists.id]);
      } else {
        await client.query(`INSERT INTO separation_items (separation_id, product_id, qty_requested, quantity) VALUES ($1, $2, $3, 0)`, [id, item.product_id, item.quantity]);
      }
    }

    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'EDITAR_SEPARACAO', { id_separacao: id, edicoes: 'Dados ou itens do pedido alterados' }, getClientIp(req), client);
    await client.query('COMMIT');
    if ((req as any).io) (req as any).io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
};

// ♻️ NOVA FUNÇÃO: Criar um pedido de Devolução
export const createReturn = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { items } = req.body;
  const userId = (req as any).user.id;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    for (const item of items) {
      await client.query(
        `INSERT INTO separation_returns (separation_id, product_id, quantity, status) VALUES ($1, $2, $3, 'pendente')`,
        [id, item.product_id, item.quantity]
      );
    }
    
    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'CRIAR_DEVOLUCAO', { id_separacao_origem: id }, getClientIp(req), client);
    await client.query('COMMIT');
    if ((req as any).io) (req as any).io.emit('separations_update');
    res.status(201).json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
};

// 🛡️ NOVA FUNÇÃO: Aprovar ou Rejeitar a Devolução (Almoxarifado)
export const updateReturnStatus = async (req: Request, res: Response) => {
  const { returnId } = req.params;
  const { status } = req.body; 
  const userId = (req as any).user.id;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const userCheck = await client.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') throw new Error('Acesso negado.');

    const retRes = await client.query('SELECT * FROM separation_returns WHERE id = $1 FOR UPDATE', [returnId]);
    if (retRes.rows.length === 0) throw new Error('Devolução não encontrada');
    const ret = retRes.rows[0];

    if (ret.status !== 'pendente') throw new Error('Esta devolução já foi processada.');

    await client.query('UPDATE separation_returns SET status = $1 WHERE id = $2', [status, returnId]);

    // Se aprovado, devolve a quantidade ao stock físico (on_hand)
    if (status === 'aprovado') {
       await client.query('UPDATE stock SET quantity_on_hand = quantity_on_hand + $1 WHERE product_id = $2', [ret.quantity, ret.product_id]);
    }

    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'PROCESSAR_DEVOLUCAO', { id_devolucao: returnId, novo_status: status }, getClientIp(req), client);
    await client.query('COMMIT');
    if ((req as any).io) (req as any).io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
};
