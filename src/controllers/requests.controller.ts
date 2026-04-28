// src/controllers/requests.controller.ts

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
              json_build_object(
                'id', ri.id, 
                'quantity_requested', ri.quantity_requested, 
                'quantity_delivered', ri.quantity_delivered, 
                'custom_product_name', ri.custom_product_name, 
                'observation', ri.observation, 
                'client_service', ri.client_service, 
                'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit, 'tags', pr.tags, 'unit_price', pr.unit_price) ELSE NULL END
              )
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
              json_build_object(
                'id', ri.id, 
                'quantity_requested', ri.quantity_requested, 
                'quantity_delivered', ri.quantity_delivered, 
                'custom_product_name', ri.custom_product_name, 
                'observation', ri.observation, 
                'client_service', ri.client_service, 
                'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit, 'tags', pr.tags, 'unit_price', pr.unit_price) ELSE NULL END
              )
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
  const { sector, items, op_code } = req.body; 
  const client = await pool.connect();
  
  try {
    validatePositiveItems(items);
    await client.query('BEGIN');

    // =========================================================================
    // 🛡️ 1. REGRA DE NEGÓCIO: VERIFICA SE A OP É OBRIGATÓRIA (BASEADO EM TAGS)
    // =========================================================================
    let requiresOp = false;
    // 🟢 INSUMOS ADICIONADOS NA LISTA DE ISENÇÃO DO BACKEND
    const exemptTags = ['camisetas', 'camiseta', 'epi', 'ferramentas', 'insumos', 'insumo'];
    
    // Pega apenas os IDs válidos (ignora itens 'custom' genéricos)
    const productIds = items
      .map((i: any) => i.product_id)
      .filter((id: any) => id && id !== 'custom');

    // Se o pedido tem algum item "avulso/genérico", a OP é obrigatória
    if (items.length > productIds.length) {
        requiresOp = true;
    } else if (productIds.length > 0) {
        // Busca as tags dos produtos lá no banco de dados
        const productsQuery = await client.query(
            'SELECT id, tags, category, grupo FROM products WHERE id = ANY($1::uuid[])', 
            [productIds]
        );
        
        for (const product of productsQuery.rows) {
            let tags = Array.isArray(product.tags) ? product.tags.map((t: string) => t.trim().toLowerCase()) : [];
            
            // Se as tags estiverem vazias, usamos a Categoria ou Grupo para a isenção (igual ao frontend)
            if (tags.length === 0) {
                if (product.category) tags.push(product.category.trim().toLowerCase());
                else if (product.grupo) tags.push(product.grupo.trim().toLowerCase());
            }

            const isExempt = tags.some((tag: string) => exemptTags.includes(tag));
            
            // Se achar UM produto que não tem a tag de isenção, exige a OP e para de procurar
            if (!isExempt) {
                requiresOp = true;
                break;
            }
        }
    }

    // =========================================================================
    // 🛡️ 2. VALIDAÇÃO E VÍNCULO DA OP
    // =========================================================================
    let client_service_id = null;

    if (op_code) {
        // Se ele digitou uma OP (mesmo sendo isento, a gente vincula pra ficar organizado)
        const opCheck = await client.query('SELECT id, status FROM client_services WHERE op_code = $1', [op_code]);
        if (opCheck.rows.length === 0) throw new Error("OP_NAO_ENCONTRADA");
        
        const opStatus = opCheck.rows[0].status;
        if (opStatus === 'finalizada' || opStatus === 'encerrada') throw new Error("OP_FINALIZADA");
        
        client_service_id = opCheck.rows[0].id;
    } else if (requiresOp) {
        // Se a OP é obrigatória e ele não digitou nada
        throw new Error("OP_OBRIGATORIA_TAGS");
    }

    // =========================================================================
    // 🟢 INSERÇÃO DO PEDIDO
    // =========================================================================
    const reqRes = await client.query(
      'INSERT INTO requests (requester_id, sector, status, client_service_id) VALUES ($1, $2, $3, $4) RETURNING id', 
      [userId, sector, 'aberto', client_service_id]
    );
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
      
      await client.query(
        'INSERT INTO request_items (request_id, product_id, custom_product_name, quantity_requested, observation, client_service) VALUES ($1, $2, $3, $4, $5, $6)', 
        [requestId, productId, customName, item.quantity, item.observation || null, item.client_service || null]
      );
    }
    
    await createLog(userId, 'CRIAR_SOLICITACAO', { id_solicitacao: requestId, setor: sector, total_itens: items.length }, getClientIp(req), client);
    await client.query('COMMIT');

    const fullReqQuery = `SELECT r.*, json_build_object('name', p.name, 'sector', p.sector) as requester, (SELECT COALESCE(json_agg(json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'quantity_delivered', ri.quantity_delivered, 'custom_product_name', ri.custom_product_name, 'observation', ri.observation, 'client_service', ri.client_service, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit, 'tags', pr.tags) ELSE NULL END)), '[]'::json) FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id WHERE ri.request_id = r.id) as request_items FROM requests r LEFT JOIN profiles p ON r.requester_id = p.id WHERE r.id = $1`;
    const { rows: fullReqRows } = await client.query(fullReqQuery, [requestId]);
    
    if ((req as any).io) {
        const notificationData = { id: `req-${requestId}-${Date.now()}`, message: `📢 Nova solicitação do setor: ${sector}`, action: 'Ver Pedidos', type: 'solicitacao' };
        (req as any).io.to(['almoxarife', 'admin', 'escritorio']).emit('new_request_notification', notificationData);
        (req as any).io.to(['almoxarife', 'admin', 'escritorio']).emit('new_request', fullReqRows[0]);
        (req as any).io.emit('refresh_stock'); 
    }

    const dataAtual = new Date();
    const dataFormatada = dataAtual.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', timeZone: 'America/Sao_Paulo' });
    const horaFormatada = dataAtual.toLocaleTimeString('pt-BR', { hour: '2-digit', minute: '2-digit', timeZone: 'America/Sao_Paulo' });

    let listaMateriais = '';
    const itemsDetail = fullReqRows[0].request_items || [];
    
    itemsDetail.forEach((reqItem: any) => {
        const qtd = reqItem.quantity_requested;
        const nomeProduto = reqItem.products ? reqItem.products.name : (reqItem.custom_product_name || 'Produto Genérico');
        const skuProduto = reqItem.products?.sku ? `SKU: ${reqItem.products.sku}` : 'SKU: N/A';
        listaMateriais += `\n- ${qtd} un. ${nomeProduto} | ${skuProduto}`;
    });

    const nomeSolicitante = fullReqRows[0].requester?.name || 'Usuário';
    
    // Deixa o aviso da OP na mensagem do WhatsApp apenas se houver OP
    const avisoOp = op_code ? `\nOP: ${op_code}` : `\nOP: Isento (EPI/Ferramenta/Insumo)`;
    const mensagemPersonalizada = `Setor: ${sector}${avisoOp}\nData/Hora: ${dataFormatada} - ${horaFormatada}\nMateriais:${listaMateriais}`;

    sendPushNotificationToRole('almoxarife', `Novo Pedido de ${nomeSolicitante}`, mensagemPersonalizada, '/requests');

    res.status(201).json({ success: true, id: requestId });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    
    // Tratamento dos erros para o Frontend
    if (error.message === "OP_OBRIGATORIA_TAGS") return res.status(400).json({ error: "É obrigatório informar o número da OP para estes tipos de produtos." });
    if (error.message === "OP_NAO_ENCONTRADA") return res.status(404).json({ error: "OP não encontrada no sistema. Verifique o número digitado." });
    if (error.message === "OP_FINALIZADA") return res.status(400).json({ error: "Essa OP ja foi finalizada, verifique a OP correta" });
    
    res.status(error.message.includes('Estoque disponível insuficiente') ? 400 : 500).json({ error: `Erro Técnico: ${error.message}` }); 
  } finally { 
    client.release(); 
  }
};

export const updateRequestStatus = async (req: Request, res: Response) => {
  const { id } = req.params;
  const userId = (req as any).user.id;
  const { status, rejection_reason, adjusted_items } = req.body;
  const client = await pool.connect();
  
  try {
    const userCheck = await pool.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') return res.status(403).json({ error: 'Sem permissão.' });

    await client.query('BEGIN');
    const currentRes = await client.query('SELECT status FROM requests WHERE id = $1 FOR UPDATE', [id]);
    if (!currentRes.rows[0]?.status) throw new Error("Solicitação não encontrada");
    const currentStatus = currentRes.rows[0].status;

    if (adjusted_items && Array.isArray(adjusted_items)) {
       for (const adj of adjusted_items) {
          const itemCheck = await client.query('SELECT product_id, quantity_requested, quantity_delivered FROM request_items WHERE id = $1', [adj.id]);
          
          if (itemCheck.rows.length > 0) {
             const item = itemCheck.rows[0];
             const oldReserved = parseFloat(item.quantity_delivered ?? item.quantity_requested);
             const newReserved = parseFloat(adj.quantity_delivered);
             
             await client.query('UPDATE request_items SET quantity_delivered = $1 WHERE id = $2', [newReserved, adj.id]);
             
             if (item.product_id && oldReserved !== newReserved && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
                const delta = newReserved - oldReserved;
                await client.query('UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) + $1) WHERE product_id = $2', [delta, item.product_id]);
             }
          }
       }
    }

    const itemsRes = await client.query('SELECT product_id, quantity_requested, quantity_delivered FROM request_items WHERE request_id = $1 ORDER BY product_id', [id]);
    
    if (status === 'entregue' && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
      for (const item of itemsRes.rows) {
        if (item.product_id) {
          const finalQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
          const stockCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1 FOR UPDATE', [item.product_id]);
          if (parseFloat(stockCheck.rows[0]?.quantity_on_hand || 0) < finalQty) throw new Error(`Furo de Estoque no produto ID ${item.product_id}.`);
          await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand - $1, quantity_reserved = GREATEST(0, quantity_reserved - $1) WHERE product_id = $2`, [finalQty, item.product_id]);
        }
      }
    } 
    else if (status === 'rejeitado' && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
      for (const item of itemsRes.rows) {
        const finalQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
        if (item.product_id) await client.query(`UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1) WHERE product_id = $2`, [finalQty, item.product_id]);
      }
    }
    else if (status === 'devolvido' && currentStatus === 'entregue') {
      for (const item of itemsRes.rows) {
        const finalQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
        if (item.product_id) await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand + $1 WHERE product_id = $2`, [finalQty, item.product_id]);
      }
    }

    await client.query('UPDATE requests SET status = $1, rejection_reason = $2 WHERE id = $3', [status, rejection_reason || null, id]);
    
    const logAction = status === 'entregue' ? 'ENTREGAR_SOLICITACAO' : status === 'rejeitado' ? 'REJEITAR_SOLICITACAO' : status === 'devolvido' ? 'DEVOLVER_SOLICITACAO' : 'ATUALIZAR_STATUS_SOLICITACAO';
    await createLog(userId, logAction, { id_solicitacao: id, novo_status: status, motivo: rejection_reason || 'N/A' }, getClientIp(req), client);
    
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

    if (status === 'rejeitado' || status === 'entregue' || status === 'devolvido') throw new Error('Não é possível cancelar no estado atual.');
    
    if (status === 'aberto' || status === 'aprovado') {
       const itemsRes = await client.query('SELECT product_id, quantity_requested, quantity_delivered FROM request_items WHERE request_id = $1', [id]);
       for (const item of itemsRes.rows) {
         const finalQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
         if (item.product_id) await client.query(`UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1) WHERE product_id = $2`, [finalQty, item.product_id]);
       }
    }

    await client.query("UPDATE requests SET status = 'rejeitado', rejection_reason = 'Cancelado pelo usuário/sistema' WHERE id = $1", [id]);
    
    await createLog(userId, 'CANCELAR_SOLICITACAO', { id_solicitacao: id, status_anterior: status }, getClientIp(req), client);
    await client.query('COMMIT');
    
    if ((req as any).io) { (req as any).io.emit('refresh_requests'); (req as any).io.emit('refresh_stock'); }
    res.json({ success: true, message: 'Pedido cancelado.' });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
};
