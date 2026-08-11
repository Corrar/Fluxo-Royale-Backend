// src/controllers/requests.controller.ts

import { Request, Response } from 'express';
import { pool } from '../db';
import { createLog } from '../utils/logger';
import { getClientIp } from '../utils/ip';
import { sendPushNotificationToRole } from '../utils/notifications';
import { validatePositiveItems } from '../middlewares/validators';
import { setStockAudit } from '../utils/stockAudit';

export const getRequests = async (req: Request, res: Response) => {
  try {
    const query = `
      WITH FilteredRequests AS (
          SELECT * FROM requests 
          WHERE status IN ('aberto', 'aprovado') 
             OR date_trunc('month', created_at) = date_trunc('month', NOW())
          ORDER BY created_at DESC LIMIT 1000
      )
      SELECT r.*, 
          cs.op_code,
          json_build_object('name', p.name, 'sector', p.sector) as requester,
          COALESCE(ri_agg.items, '[]'::json) as request_items
      FROM FilteredRequests r
      LEFT JOIN profiles p ON r.requester_id = p.id
      LEFT JOIN client_services cs ON r.client_service_id = cs.id
      LEFT JOIN (
          SELECT ri.request_id, json_agg(
              json_build_object(
                'id', ri.id, 
                'quantity_requested', ri.quantity_requested, 
                'quantity_delivered', ri.quantity_delivered, 
                'quantity_returned', ri.quantity_returned, 
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
          WHERE requester_id = $1 AND (status IN ('aberto', 'aprovado') OR date_trunc('month', created_at) = date_trunc('month', NOW()))
          ORDER BY created_at DESC LIMIT 1000
      )
      SELECT r.*, 
          cs.op_code, 
          COALESCE(ri_agg.items, '[]'::json) as request_items
      FROM FilteredRequests r
      LEFT JOIN client_services cs ON r.client_service_id = cs.id
      LEFT JOIN (
          SELECT ri.request_id, json_agg(
              json_build_object(
                'id', ri.id, 
                'quantity_requested', ri.quantity_requested, 
                'quantity_delivered', ri.quantity_delivered, 
                'quantity_returned', ri.quantity_returned, 
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

    // 🛑 [NOVO] Passo 1: Buscar o cargo do usuário que está fazendo o pedido
    // Precisamos saber se ele é o almoxarife para aplicar a regra da tag MIN-TAI.
    const userCheck = await client.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    const userRole = userCheck.rows[0]?.role;

    // =========================================================================
    // 🛡️ 1. REGRA DE NEGÓCIO: VERIFICA SE A OP É OBRIGATÓRIA (BASEADO EM TAGS) E BLOQUEIO DE MIN-TAI
    // =========================================================================
    let requiresOp = false;
    const exemptTags = ['camisetas', 'camiseta', 'epi', 'ferramentas', 'ferramenta', 'insumos', 'insumo', 'feira'];
    
    const productIds = items
      .map((i: any) => i.product_id)
      .filter((id: any) => id && id !== 'custom');

    if (items.length > productIds.length) {
        requiresOp = true;
    } else if (productIds.length > 0) {
        const productsQuery = await client.query(
            'SELECT id, tags FROM products WHERE id = ANY($1::uuid[])', 
            [productIds]
        );
        
        for (const product of productsQuery.rows) {
            let tags: string[] = [];
            
            // Normalização das tags
            if (Array.isArray(product.tags)) {
                tags.push(...product.tags.map((t: string) => String(t).trim().toLowerCase()));
            } else if (typeof product.tags === 'string' && product.tags.trim() !== '') {
                try {
                    const parsed = JSON.parse(product.tags);
                    if (Array.isArray(parsed)) tags.push(...parsed.map((t: string) => String(t).trim().toLowerCase()));
                    else tags.push(product.tags.trim().toLowerCase());
                } catch(e) {
                    tags.push(product.tags.trim().toLowerCase());
                }
            }

            // 🛑 [NOVO] Passo 2: Verificamos se o array de tags contém 'min-tai'
            const hasMinTaiTag = tags.some((tag: string) => tag === 'min-tai');
            
            // 🛑 [NOVO] Passo 3: Se tiver a tag e não for almoxarife, bloqueamos a operação!
            if (hasMinTaiTag && userRole !== 'almoxarife') {
                throw new Error("MIN_TAI_RESTRICTED");
            }

            // Verificação original da OP Obrigatória
            const isExempt = tags.some((tag: string) => exemptTags.includes(tag));
            if (!isExempt) {
                requiresOp = true;
                // Removido o 'break;' daqui para garantir que o loop avalie 
                // TODOS os produtos para a trava do MIN-TAI, e não pare no primeiro.
            }
        }
    }

    // =========================================================================
    // 🛡️ 2. VALIDAÇÃO E VÍNCULO DA OP
    // =========================================================================
    let client_service_id = null;

    if (op_code) {
        const opCheck = await client.query('SELECT id, status FROM client_services WHERE op_code = $1', [op_code]);
        if (opCheck.rows.length === 0) throw new Error("OP_NAO_ENCONTRADA");
        
        const opStatus = opCheck.rows[0].status;
        if (opStatus === 'finalizada' || opStatus === 'encerrada') throw new Error("OP_FINALIZADA");
        
        client_service_id = opCheck.rows[0].id;
    } else if (requiresOp) {
        throw new Error("OP_OBRIGATORIA_TAGS");
    }

    // =========================================================================
    // 🟢 3. INSERÇÃO DO PEDIDO BASE
    // =========================================================================
    const reqRes = await client.query(
      'INSERT INTO requests (requester_id, sector, status, client_service_id) VALUES ($1, $2, $3, $4) RETURNING id', 
      [userId, sector, 'aberto', client_service_id]
    );
    const requestId = reqRes.rows[0].id;

    await setStockAudit(client, 'SOLICITACAO_RESERVA', userId, `solicitacao:${requestId}`);

    const sortedItems = [...items].sort((a, b) => {
       if (!a.product_id) return 1; if (!b.product_id) return -1;
       return String(a.product_id).localeCompare(String(b.product_id));
    });

    // =========================================================================
    // 🌉 4. A PONTE MÁGICA: RESERVA NORMAL OU ENVIO PARA O KANBAN 3D
    // =========================================================================
    for (const item of sortedItems) {
      const isCustom = item.product_id === 'custom' || !item.product_id;
      const productId = isCustom ? null : item.product_id;
      const customName = isCustom ? item.custom_name : null;
      const priority = item.priority || 'Média'; // Lê a prioridade do frontend
      let is3D = false;

      if (productId) {
        const stockLock = await client.query(
            `SELECT (COALESCE(quantity_on_hand, 0) - COALESCE(quantity_reserved, 0)) as available
             FROM stock WHERE product_id = $1 FOR UPDATE`,
            [productId]
        );
        const productCheck = await client.query(`SELECT is_3d FROM products WHERE id = $1`, [productId]);

        const available = parseFloat(stockLock.rows[0]?.available || 0);
        is3D = productCheck.rows[0]?.is_3d || false;

        if (is3D) {
            let missingQty = item.quantity;
            let reservedQty = 0;

            if (available > 0) {
                reservedQty = Math.min(item.quantity, available);
                missingQty = item.quantity - reservedQty;
                
                await client.query(
                  `UPDATE stock SET quantity_reserved = COALESCE(quantity_reserved, 0) + $1 WHERE product_id = $2`, 
                  [reservedQty, productId]
                );
            }

            if (missingQty > 0) {
                const kanbanOpNumber = op_code ? op_code : 'Interno';
                
                const notesInfo = `⚠️ RESUMO DO PEDIDO:\n- A Produzir: ${missingQty} un.\n- Já em Estoque: ${reservedQty} un.\n- Total Solicitado: ${item.quantity} un.\n\n📝 OBSERVAÇÕES:\n${item.observation || 'Nenhuma'}`;

                await client.query(
                   `INSERT INTO demands_3d (product_id, request_id, quantity, op_number, priority, notes) 
                    VALUES ($1, $2, $3, $4, $5, $6)`,
                   [productId, requestId, missingQty, kanbanOpNumber, priority, notesInfo]
                );
            }
        } 
        else {
            if (available < item.quantity) throw new Error(`Estoque disponível insuficiente para o produto ID: ${productId}`);
            await client.query(`UPDATE stock SET quantity_reserved = COALESCE(quantity_reserved, 0) + $1 WHERE product_id = $2`, [item.quantity, productId]);
        }
      }
      
      await client.query(
        'INSERT INTO request_items (request_id, product_id, custom_product_name, quantity_requested, observation, client_service, unit_price) VALUES ($1, $2, $3, $4, $5, $6, (SELECT unit_price FROM products WHERE id = $2))',
        [requestId, productId, customName, item.quantity, item.observation || null, item.client_service || null]
      );
    }
    
    await createLog(userId, 'CRIAR_SOLICITACAO', { id_solicitacao: requestId, setor: sector, total_itens: items.length }, getClientIp(req), client);
    await client.query('COMMIT');

    const fullReqQuery = `
      SELECT r.*, 
             cs.op_code, 
             json_build_object('name', p.name, 'sector', p.sector) as requester, 
             (SELECT COALESCE(json_agg(json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'quantity_delivered', ri.quantity_delivered, 'quantity_returned', ri.quantity_returned, 'custom_product_name', ri.custom_product_name, 'observation', ri.observation, 'client_service', ri.client_service, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit, 'tags', pr.tags) ELSE NULL END)), '[]'::json) FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id WHERE ri.request_id = r.id) as request_items 
      FROM requests r 
      LEFT JOIN profiles p ON r.requester_id = p.id 
      LEFT JOIN client_services cs ON r.client_service_id = cs.id 
      WHERE r.id = $1`;
    const { rows: fullReqRows } = await client.query(fullReqQuery, [requestId]);
    
    if ((req as any).io) {
        const notificationData = { id: `req-${requestId}-${Date.now()}`, message: `📢 Nova solicitação do setor: ${sector}`, action: 'Ver Pedidos', type: 'solicitacao' };
        (req as any).io.to(['almoxarife', 'admin', 'escritorio']).emit('new_request_notification', notificationData);
        
        (req as any).io.to(['almoxarife', 'admin', 'escritorio']).emit('new_request', fullReqRows[0]);
        
        const changedProducts = sortedItems.map(item => item.product_id).filter(id => id && id !== 'custom');
        if (changedProducts.length > 0) {
            (req as any).io.emit('stock_updated', { changedProducts }); 
        }
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
    
    const avisoOp = op_code ? `\nOP: ${op_code}` : `\nOP: Isento (EPI/Ferramenta/Insumo)`;
    const mensagemPersonalizada = `Setor: ${sector}${avisoOp}\nData/Hora: ${dataFormatada} - ${horaFormatada}\nMateriais:${listaMateriais}`;

    sendPushNotificationToRole('almoxarife', `Novo Pedido de ${nomeSolicitante}`, mensagemPersonalizada, '/requests');

    res.status(201).json({ success: true, id: requestId });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    
    // 🛑 [NOVO] Passo 4: Retornamos o erro amigável caso a trava de segurança tenha sido acionada
    if (error.message === "MIN_TAI_RESTRICTED") return res.status(403).json({ error: "Acesso negado. Apenas o setor do Almoxarifado pode gerenciar e solicitar itens MIN-TAI." });
    
    if (error.message === "OP_OBRIGATORIA_TAGS") return res.status(400).json({ error: "É obrigatório informar o número da OP para estes tipos de produtos." });
    if (error.message === "OP_NAO_ENCONTRADA") return res.status(404).json({ error: "OP não encontrada no sistema. Verifique o número digitado." });
    if (error.message === "OP_FINALIZADA") return res.status(400).json({ error: "Essa OP ja foi finalizada, verifique a OP correta" });
    
    res.status(error.message.includes('Estoque disponível insuficiente') ? 400 : 500).json({ error: `Erro Técnico: ${error.message}` }); 
  } finally { 
    client.release(); 
  }
};

const getReserved3DPortion = async (client: any, requestId: string, productId: string, requestedQty: number): Promise<number> => {
  const dem = await client.query(
    `SELECT COALESCE(SUM(quantity), 0) as pending FROM demands_3d WHERE request_id = $1 AND product_id = $2 AND status != 'Concluída'`,
    [requestId, productId]
  );
  return Math.max(0, requestedQty - parseFloat(dem.rows[0].pending));
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

    const allowedTransitions: Record<string, string[]> = {
      'aprovado':  ['aberto'],
      'entregue':  ['aberto', 'aprovado'],
      'rejeitado': ['aberto', 'aprovado'],
      'devolvido': ['entregue'],
    };
    if (!allowedTransitions[status] || !allowedTransitions[status].includes(currentStatus)) {
      throw new Error(`Transição de status inválida: "${currentStatus}" → "${status}".`);
    }

    const auditActions: Record<string, string> = {
      'aprovado': 'SOLICITACAO_APROVACAO',
      'entregue': 'SOLICITACAO_ENTREGA',
      'rejeitado': 'SOLICITACAO_REJEICAO',
      'devolvido': 'SOLICITACAO_DEVOLUCAO',
    };
    await setStockAudit(client, auditActions[status], userId, `solicitacao:${id}`);

    if (adjusted_items && Array.isArray(adjusted_items)) {
       for (const adj of adjusted_items) {
          const itemCheck = await client.query('SELECT ri.product_id, ri.quantity_requested, ri.quantity_delivered, p.is_3d FROM request_items ri LEFT JOIN products p ON ri.product_id = p.id WHERE ri.id = $1', [adj.id]);

          if (itemCheck.rows.length > 0) {
             const item = itemCheck.rows[0];
             const oldReserved = parseFloat(item.quantity_delivered ?? item.quantity_requested);
             const newReserved = parseFloat(adj.quantity_delivered);
             if (isNaN(newReserved) || newReserved < 0) throw new Error('Quantidade ajustada inválida.');

             await client.query('UPDATE request_items SET quantity_delivered = $1 WHERE id = $2', [newReserved, adj.id]);

             if (item.product_id && !item.is_3d && oldReserved !== newReserved && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
                const delta = newReserved - oldReserved;
                const stockVal = await client.query('SELECT quantity_on_hand, quantity_reserved FROM stock WHERE product_id = $1 FOR UPDATE', [item.product_id]);
                if (delta > 0) {
                    const available = parseFloat(stockVal.rows[0]?.quantity_on_hand || 0) - parseFloat(stockVal.rows[0]?.quantity_reserved || 0);
                    if (available < delta) throw new Error(`Estoque disponível insuficiente para aumentar a quantidade do produto ID ${item.product_id}.`);
                }
                await client.query('UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) + $1) WHERE product_id = $2', [delta, item.product_id]);
             }
          }
       }
    }

    const itemsRes = await client.query('SELECT ri.product_id, ri.quantity_requested, ri.quantity_delivered, p.is_3d FROM request_items ri LEFT JOIN products p ON ri.product_id = p.id WHERE ri.request_id = $1 ORDER BY ri.product_id', [id]);
    
    if (status === 'entregue' && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
      for (const item of itemsRes.rows) {
        if (item.product_id) {
          const finalQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
          const stockCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1 FOR UPDATE', [item.product_id]);
          if (parseFloat(stockCheck.rows[0]?.quantity_on_hand || 0) < finalQty) throw new Error(`Furo de Estoque no produto ID ${item.product_id}.`);
          
          const reserveRelease = item.is_3d
            ? await getReserved3DPortion(client, id, item.product_id, parseFloat(item.quantity_requested))
            : finalQty;
          await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand - $1, quantity_reserved = GREATEST(0, quantity_reserved - $2) WHERE product_id = $3`, [finalQty, reserveRelease, item.product_id]);
        }
      }
    }
    else if (status === 'rejeitado' && (currentStatus === 'aberto' || currentStatus === 'aprovado')) {
      for (const item of itemsRes.rows) {
        if (item.product_id) {
            const finalQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
            const reserveRelease = item.is_3d
              ? await getReserved3DPortion(client, id, item.product_id, parseFloat(item.quantity_requested))
              : finalQty;
            await client.query(`UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1) WHERE product_id = $2`, [reserveRelease, item.product_id]);
        }
      }
      await client.query(`UPDATE demands_3d SET status = 'Cancelada' WHERE request_id = $1 AND status NOT IN ('Concluída', 'Cancelada')`, [id]);
    }
    else if (status === 'devolvido' && currentStatus === 'entregue') {
      for (const item of itemsRes.rows) {
        if (item.product_id) {
            const finalQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
            await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand + $1 WHERE product_id = $2`, [finalQty, item.product_id]);
        }
      }
    }

    await client.query('UPDATE requests SET status = $1, rejection_reason = $2 WHERE id = $3', [status, rejection_reason || null, id]);
    
    const logAction = status === 'entregue' ? 'ENTREGAR_SOLICITACAO' : status === 'rejeitado' ? 'REJEITAR_SOLICITACAO' : status === 'devolvido' ? 'DEVOLVER_SOLICITACAO' : 'ATUALIZAR_STATUS_SOLICITACAO';
    const logChanges: any = { id_solicitacao: { new: id }, status: { old: currentStatus, new: status } };
    if (rejection_reason) logChanges.motivo = { new: rejection_reason };
    await createLog(userId, logAction, { changes: logChanges }, getClientIp(req), client);
    
    await client.query('COMMIT');

    if ((req as any).io) { 
        (req as any).io.emit('request_updated', { id, status, rejection_reason }); 
        
        const changedProducts = itemsRes.rows.map(item => item.product_id).filter(id => id);
        if (changedProducts.length > 0) {
            (req as any).io.emit('stock_updated', { changedProducts });
        }
    }
    
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

    await setStockAudit(client, 'SOLICITACAO_CANCELAMENTO', userId, `solicitacao:${id}`);

    if (status === 'rejeitado' || status === 'entregue' || status === 'devolvido') throw new Error('Não é possível cancelar no estado atual.');
    
    let itemsRes: any;
    if (status === 'aberto' || status === 'aprovado') {
       itemsRes = await client.query('SELECT ri.product_id, ri.quantity_requested, ri.quantity_delivered, p.is_3d FROM request_items ri LEFT JOIN products p ON ri.product_id = p.id WHERE ri.request_id = $1', [id]);
       for (const item of itemsRes.rows) {
         if (item.product_id) {
            const finalQty = item.is_3d
              ? await getReserved3DPortion(client, id, item.product_id, parseFloat(item.quantity_requested))
              : parseFloat(item.quantity_delivered ?? item.quantity_requested);
            if (finalQty > 0) {
              await client.query(`UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1) WHERE product_id = $2`, [finalQty, item.product_id]);
            }
         }
       }
    }

    await client.query("UPDATE requests SET status = 'rejeitado', rejection_reason = 'Cancelado pelo usuário/sistema' WHERE id = $1", [id]);
    
    await client.query("UPDATE demands_3d SET status = 'Cancelada' WHERE request_id = $1 AND status != 'Concluída'", [id]);

    await createLog(userId, 'CANCELAR_SOLICITACAO', { id_solicitacao: id, status_anterior: status }, getClientIp(req), client);
    await client.query('COMMIT');
    
    if ((req as any).io) { 
        (req as any).io.emit('request_updated', { id, status: 'rejeitado', rejection_reason: 'Cancelado pelo usuário/sistema' }); 
        
        if (itemsRes && itemsRes.rows) {
            const changedProducts = itemsRes.rows.map((item: any) => item.product_id).filter((id: any) => id);
            if (changedProducts.length > 0) {
                (req as any).io.emit('stock_updated', { changedProducts });
            }
        }
    }
    
    res.json({ success: true, message: 'Pedido cancelado.' });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
};

export const partialReturnRequest = async (req: Request, res: Response) => {
  const { id } = req.params;
  const userId = (req as any).user.id;
  const { returns } = req.body;
  const client = await pool.connect();
  
  try {
    const userCheck = await pool.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    if (userCheck.rows[0]?.role !== 'admin' && userCheck.rows[0]?.role !== 'almoxarife') return res.status(403).json({ error: 'Sem permissão.' });

    await client.query('BEGIN');

    const reqRes = await client.query('SELECT status, client_service_id FROM requests WHERE id = $1 FOR UPDATE', [id]);
    if (!reqRes.rows[0] || reqRes.rows[0].status !== 'entregue') {
        throw new Error("Apenas solicitações 'entregues' podem ter itens devolvidos.");
    }
    const client_service_id = reqRes.rows[0].client_service_id;

    await setStockAudit(client, 'SOLICITACAO_DEVOLUCAO_PARCIAL', userId, `solicitacao:${id}`);

    for (const ret of returns) {
      if (ret.quantity_to_return <= 0) continue;

      const itemCheck = await client.query(
          'SELECT ri.product_id, ri.quantity_delivered, ri.quantity_requested, ri.quantity_returned, p.is_3d FROM request_items ri LEFT JOIN products p ON ri.product_id = p.id WHERE ri.id = $1 FOR UPDATE OF ri',
          [ret.request_item_id]
      );

      const item = itemCheck.rows[0];
      if (!item) throw new Error('Item da solicitação não encontrado.');
      const delivered = parseFloat(item.quantity_delivered ?? item.quantity_requested);
      const alreadyReturned = parseFloat(item.quantity_returned ?? 0);
      const returnQty = parseFloat(ret.quantity_to_return);

      if (alreadyReturned + returnQty > delivered) {
          throw new Error(`Não podes devolver mais do que foi entregue para o produto.`);
      }

      await client.query('UPDATE request_items SET quantity_returned = COALESCE(quantity_returned, 0) + $1 WHERE id = $2', [returnQty, ret.request_item_id]);

      if (item.product_id) {
          await client.query('UPDATE stock SET quantity_on_hand = quantity_on_hand + $1 WHERE product_id = $2', [returnQty, item.product_id]);
      }

      if (client_service_id && item.product_id) {
          await client.query(`
              INSERT INTO op_returns (client_service_id, product_id, quantity, user_id, observation)
              VALUES ($1, $2, $3, $4, $5)
          `, [client_service_id, item.product_id, returnQty, userId, "Devolução parcial via Solicitação"]);
      }
    }

    await createLog(userId, 'DEVOLUCAO_PARCIAL', { id_solicitacao: id }, getClientIp(req), client);
    
    await client.query('COMMIT');

    if ((req as any).io) { 
        (req as any).io.emit('refresh_requests');
        (req as any).io.emit('refresh_stock');
    }

    res.json({ success: true, message: "Devolução parcial processada com sucesso!" });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message || 'Erro ao processar devolução parcial' });
  } finally { client.release(); }
};
