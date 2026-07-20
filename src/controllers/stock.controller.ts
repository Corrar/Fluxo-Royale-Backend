// src/controllers/stock.controller.ts

import { Request, Response } from 'express';
import { pool } from '../db';
import { createLog } from '../utils/logger';
import { getClientIp } from '../utils/ip';
import { sendPushNotificationToRole } from '../utils/notifications';
import { validatePositiveItems } from '../middlewares/validators';
import { setStockAudit } from '../utils/stockAudit';

// =========================================================================
// CONSULTA DO LEDGER DE MOVIMENTAÇÕES (histórico imutável do estoque)
// =========================================================================
export const getStockMovements = async (req: Request, res: Response) => {
  try {
    const { product_id, action, days, search } = req.query;
    const params: any[] = [];

    params.push(String(Math.min(Number(days) || 30, 365)));
    let where = `WHERE m.created_at > NOW() - ($${params.length} || ' days')::interval`;

    if (product_id) {
      params.push(product_id);
      where += ` AND m.product_id = $${params.length}`;
    }
    if (action) {
      params.push(action);
      where += ` AND m.action = $${params.length}`;
    }
    if (search) {
      params.push(`%${search}%`);
      where += ` AND (p.name ILIKE $${params.length} OR p.sku ILIKE $${params.length})`;
    }

    params.push(Math.min(Number(req.query.limit) || 300, 1000));

    const { rows } = await pool.query(`
      SELECT m.id, m.product_id, m.on_hand_before, m.on_hand_after,
             m.reserved_before, m.reserved_after, m.on_hand_delta, m.reserved_delta,
             m.action, m.source, m.db_user, m.created_at,
             p.name as product_name, p.sku as product_sku, p.unit as product_unit,
             pf.name as user_name
      FROM stock_movements m
      LEFT JOIN products p ON p.id = m.product_id
      LEFT JOIN profiles pf ON pf.id::text = m.user_id
      ${where}
      ORDER BY m.created_at DESC
      LIMIT $${params.length}
    `, params);

    res.json(rows);
  } catch (error: any) {
    console.error('Erro ao buscar movimentações de estoque:', error);
    res.status(500).json({ error: 'Erro ao buscar movimentações de estoque' });
  }
};

export const getStock = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, json_build_object(
        'id', p.id, 
        'name', p.name, 
        'sku', p.sku, 
        'unit', p.unit, 
        'min_stock', p.min_stock, 
        'unit_price', p.unit_price, 
        'sales_price', p.sales_price, 
        'tags', p.tags
      ) as products
      FROM stock s 
      JOIN products p ON s.product_id = p.id 
      WHERE p.active = true 
      ORDER BY s.created_at DESC;
    `);
    res.json(rows);
  } catch (error: any) { 
    res.status(500).json({ error: 'Erro ao buscar estoque' }); 
  }
};

export const getStockReservations = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    const stockCheck = await pool.query('SELECT product_id FROM stock WHERE id = $1', [id]);
    
    if (stockCheck.rows.length === 0) {
      return res.status(404).json({ error: 'Estoque não encontrado' });
    }
    
    const productId = stockCheck.rows[0].product_id;
    let reservations: any[] = [];
    
    const reqRes = await pool.query(`
      SELECT r.id as request_id, COALESCE(pf.sector, r.sector) as sector, ri.quantity_requested as quantity 
      FROM request_items ri 
      JOIN requests r ON ri.request_id = r.id 
      LEFT JOIN profiles pf ON r.requester_id = pf.id 
      WHERE ri.product_id = $1 AND r.status IN ('aberto', 'aprovado') AND ri.quantity_requested > 0
    `, [productId]);
    
    const travelRes = await pool.query(`
      SELECT t.id as request_id, 'Viagem: ' || t.city as sector, ti.quantity_out as quantity 
      FROM travel_order_items ti 
      JOIN travel_orders t ON ti.travel_order_id = t.id 
      WHERE ti.product_id = $1 AND t.status IN ('pending', 'awaiting_stock') AND ti.quantity_out > 0
    `, [productId]);
    
    const sepRes = await pool.query(`
      SELECT s.id as request_id, 'Separação OP: ' || s.client_name as sector, si.quantity as quantity 
      FROM separation_items si 
      JOIN separations s ON si.separation_id = s.id 
      WHERE si.product_id = $1 AND s.status = 'em_separacao' AND si.quantity > 0
    `, [productId]);
    
    const repRes = await pool.query(`
      SELECT rep.id as request_id, 'Reposição: ' || rep.client_name as sector, ri.quantity as quantity 
      FROM replenishment_items ri 
      JOIN replenishments rep ON ri.replenishment_id = rep.id 
      WHERE ri.product_id = $1 AND rep.status = 'em_preparo' AND ri.quantity > 0
    `, [productId]);

    reservations.push(...reqRes.rows, ...travelRes.rows, ...sepRes.rows, ...repRes.rows);
    res.json(reservations);
  } catch (error: any) { 
    res.status(500).json({ error: 'Erro ao buscar reservas vinculadas' }); 
  }
};

export const updateStock = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  const { quantity_on_hand, quantity_reserved } = req.body;
  
  try {
    const userCheck = await pool.query('SELECT role, sector FROM profiles WHERE id = $1', [userId]);
    const isMaster = userCheck.rows[0].role === 'admin' || userCheck.rows[0].role === 'almoxarife';
    
    // Validação de permissões específicas para o setor de Usinagem
    if (!isMaster) {
       const stockItem = await pool.query(`SELECT p.tags FROM stock s JOIN products p ON s.product_id = p.id WHERE s.id = $1`, [id]);
       const hasTag = Array.isArray(stockItem.rows[0]?.tags) && stockItem.rows[0].tags.some((t: string) => t.toLowerCase() === 'usinagem');
       
       // 👇 CORREÇÃO: Em vez de verificar o setor, validamos se a classe é o Líder de Usinagem
       if (userCheck.rows[0].role !== 'usinagem_lider' || !hasTag) {
         return res.status(403).json({ error: 'Sem permissão. Apenas o Líder de Usinagem pode editar este item.' });
       }
    }

    const oldStock = await pool.query('SELECT quantity_on_hand, quantity_reserved, product_id FROM stock WHERE id = $1', [id]);

    // 🛡️ CORREÇÃO TYPESCRIPT APLICADA:
    let fields: string[] = [];
    let values: any[] = [];
    let index = 1;

    if (quantity_on_hand !== undefined) {
      const qty = Number(quantity_on_hand);
      if (isNaN(qty) || qty < 0) return res.status(400).json({ error: 'Quantidade em mãos inválida: deve ser um número maior ou igual a zero.' });
      fields.push(`quantity_on_hand = $${index++}`);
      values.push(qty);
    }
    if (quantity_reserved !== undefined) {
      const qty = Number(quantity_reserved);
      if (isNaN(qty) || qty < 0) return res.status(400).json({ error: 'Quantidade reservada inválida: deve ser um número maior ou igual a zero.' });
      fields.push(`quantity_reserved = $${index++}`);
      values.push(qty);
    }
    
    if (fields.length > 0) {
      // Transação própria para o contexto de auditoria valer no trigger do ledger
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        await setStockAudit(client, 'AJUSTE_MANUAL', userId, `stock:${id}`);
        values.push(id);
        await client.query(`UPDATE stock SET ${fields.join(', ')} WHERE id = $${index}`, values);

        // Registrar log da alteração
        if (oldStock.rows.length > 0) {
           await createLog(userId, 'UPDATE_STOCK', {
             stock_id: id,
             old_qty: oldStock.rows[0].quantity_on_hand,
             new_qty: quantity_on_hand
           }, getClientIp(req), client);
        }
        await client.query('COMMIT');
      } catch (err) {
        try { await client.query('ROLLBACK'); } catch(e) {}
        throw err;
      } finally {
        client.release();
      }
    }
    res.json({ success: true });
  } catch (error: any) { 
    res.status(500).json({ error: 'Erro ao ajustar estoque' }); 
  }
};

export const manualWithdrawal = async (req: Request, res: Response) => {
  const { sector, items, op_code } = req.body;
  const userId = (req as any).user.id;

  // =========================================================================
  // 🛡️ 0. VALIDAÇÃO DE SEGURANÇA DO SETOR (À PROVA DE BALAS)
  // =========================================================================
  
  // Incluímos absolutamente todos os setores usados no sistema
  const VALID_SECTORS = [
    "Elétrica", "Flow", "Esteira", "Lavadora", "Usinagem", 
    "Desenvolvimento", "Protótipo", "Engenharia", "Outros",
    "Viagem", "Terceiros", "Acumulador", "Reposição"
  ];

  // Transforma o setor recebido e a lista para letras maiúsculas.
  // Isso garante que "PROTÓTIPO" seja lido como igual a "Protótipo".
  const normalizedSector = sector ? sector.toUpperCase() : "";
  const isValidSector = VALID_SECTORS.some(s => s.toUpperCase() === normalizedSector);

  if (!isValidSector) {
    return res.status(400).json({ error: "Setor de destino inválido ou não autorizado." });
  }

  const client = await pool.connect();
  
  try {
    validatePositiveItems(items);
    await client.query('BEGIN');

    // =========================================================================
    // 🛡️ 1. REGRA DE NEGÓCIO: VERIFICA SE A OP É OBRIGATÓRIA (BASEADO EM TAGS)
    // =========================================================================
    let requiresOp = false;
    const exemptTags = ['camisetas', 'epi', 'ferramentas'];
    
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
            const tags = Array.isArray(product.tags) ? product.tags.map((t: string) => t.toLowerCase()) : [];
            const isExempt = tags.some((tag: string) => exemptTags.includes(tag));
            
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
        const opCheck = await client.query('SELECT id, status FROM client_services WHERE op_code = $1', [op_code]);
        if (opCheck.rows.length === 0) throw new Error("OP_NAO_ENCONTRADA");
        
        const opStatus = opCheck.rows[0].status;
        if (opStatus === 'finalizada' || opStatus === 'encerrada') throw new Error("OP_FINALIZADA");
        
        client_service_id = opCheck.rows[0].id;
    } else if (requiresOp) {
        throw new Error("OP_OBRIGATORIA_TAGS");
    }

    // =========================================================================
    // 🟢 INSERÇÃO DA SAÍDA MANUAL COM A OP
    // =========================================================================
    const sepRes = await client.query(
      'INSERT INTO separations (destination, status, type, client_service_id) VALUES ($1, $2, $3, $4) RETURNING id',
      [sector, 'concluida', 'manual', client_service_id]
    );

    await setStockAudit(client, 'SAIDA_MANUAL', userId, `separacao:${sepRes.rows[0].id}${op_code ? ` op:${op_code}` : ''}`);

    // Ordena por product_id para travar as linhas sempre na mesma ordem (evita deadlocks entre transações concorrentes)
    const sortedItems = [...items].sort((a, b) => String(a.product_id).localeCompare(String(b.product_id)));

    for (const item of sortedItems) {
      if (!item.product_id || !item.quantity) throw new Error("Item inválido.");

      const stCheck = await client.query('SELECT quantity_on_hand, quantity_reserved FROM stock WHERE product_id = $1 FOR UPDATE', [item.product_id]);
      const onHand = parseFloat(stCheck.rows[0]?.quantity_on_hand || 0);
      const reserved = parseFloat(stCheck.rows[0]?.quantity_reserved || 0);
      // A retirada manual só pode consumir o saldo LIVRE (físico - reservado),
      // senão ela "come" material já reservado para solicitações/separações e gera furo na entrega.
      if (onHand - reserved < item.quantity) {
        throw new Error(`Estoque disponível insuficiente ID ${item.product_id} (físico: ${onHand}, reservado: ${reserved}).`);
      }

      await client.query(
        'INSERT INTO separation_items (separation_id, product_id, quantity, observation) VALUES ($1, $2, $3, $4)',
        [sepRes.rows[0].id, item.product_id, item.quantity, item.observation || null]
      );

      await client.query('UPDATE stock SET quantity_on_hand = quantity_on_hand - $1 WHERE product_id = $2', [item.quantity, item.product_id]);
    }

    await createLog(userId, 'MANUAL_WITHDRAWAL', { separationId: sepRes.rows[0].id, sector }, getClientIp(req), client);
    await client.query('COMMIT');
    res.status(201).json({ success: true });
    
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}

    // 🟢 Tratamento de erros amigáveis para exibir no Frontend
    if (error.message === "OP_OBRIGATORIA_TAGS") return res.status(400).json({ error: "É obrigatório informar o número da OP para estes tipos de produtos." });
    if (error.message === "OP_NAO_ENCONTRADA") return res.status(404).json({ error: "OP não encontrada no sistema. Verifique o número digitado." });
    if (error.message === "OP_FINALIZADA") return res.status(400).json({ error: "Essa OP já foi finalizada, verifique a OP correta" });

    res.status(500).json({ error: error.message });
  } finally { 
    client.release(); 
  }
};

// =========================================================================
// DEVOLUÇÕES DE ORDEM DE PRODUÇÃO (OP) E NOVA ENTRADA EM LOTE (ENTRIES)
// =========================================================================

export const getOpMaterialsForReturn = async (req: Request, res: Response) => {
  const { opCode } = req.params;

  try {
    const query = `
      WITH OPData AS (
          SELECT id FROM client_services WHERE op_code = $1
      ),
      Withdrawn AS (
          SELECT 
              si.product_id,
              p.name,
              p.sku,
              SUM(si.quantity) as total_withdrawn
          FROM separations s
          JOIN separation_items si ON s.id = si.separation_id
          JOIN products p ON si.product_id = p.id
          WHERE s.client_service_id = (SELECT id FROM OPData)
          GROUP BY si.product_id, p.name, p.sku
      ),
      Returned AS (
          SELECT 
              product_id, 
              SUM(quantity) as total_returned
          FROM op_returns
          WHERE client_service_id = (SELECT id FROM OPData)
          GROUP BY product_id
      )
      SELECT 
          w.product_id,
          w.name,
          w.sku,
          w.total_withdrawn,
          COALESCE(r.total_returned, 0) as total_returned,
          (w.total_withdrawn - COALESCE(r.total_returned, 0)) as available_to_return
      FROM Withdrawn w
      LEFT JOIN Returned r ON w.product_id = r.product_id
      WHERE (w.total_withdrawn - COALESCE(r.total_returned, 0)) > 0;
    `;

    const result = await pool.query(query, [opCode]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ message: 'Nenhum material disponível para devolução nesta OP.' });
    }

    res.json(result.rows);
  } catch (error: any) {
    console.error('Erro ao buscar materiais da OP:', error);
    res.status(500).json({ error: 'Erro interno ao processar a busca da OP.' });
  }
};

export const registerReturn = async (req: Request, res: Response) => {
  const { op_code, returns } = req.body;
  const userId = (req as any).user.id;

  if (!returns || !Array.isArray(returns) || returns.length === 0) {
    return res.status(400).json({ error: 'Nenhum item de devolução fornecido.' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const opResult = await client.query('SELECT id FROM client_services WHERE op_code = $1', [op_code]);
    if (opResult.rows.length === 0) throw new Error('OP não encontrada no sistema.');
    const client_service_id = opResult.rows[0].id;

    await setStockAudit(client, 'DEVOLUCAO_OP', userId, `op:${op_code}`);

    const sortedReturns = [...returns].sort((a: any, b: any) => String(a.product_id).localeCompare(String(b.product_id)));

    for (const item of sortedReturns) {
      const returnQty = Number(item.quantity);
      if (!item.product_id || isNaN(returnQty) || returnQty <= 0) {
        throw new Error('Quantidade inválida para devolução.');
      }

      // Trava a linha do stock para serializar devoluções concorrentes do mesmo produto
      await client.query('SELECT id FROM stock WHERE product_id = $1 FOR UPDATE', [item.product_id]);

      // Nunca deixar devolver mais do que foi retirado na OP — senão o estoque infla do nada
      const balance = await client.query(`
          SELECT
            COALESCE((SELECT SUM(si.quantity) FROM separations s JOIN separation_items si ON s.id = si.separation_id
              WHERE s.client_service_id = $1 AND si.product_id = $2), 0) as total_withdrawn,
            COALESCE((SELECT SUM(quantity) FROM op_returns
              WHERE client_service_id = $1 AND product_id = $2), 0) as total_returned
      `, [client_service_id, item.product_id]);

      const availableToReturn = parseFloat(balance.rows[0].total_withdrawn) - parseFloat(balance.rows[0].total_returned);
      if (returnQty > availableToReturn) {
        throw new Error(`Devolução maior que o retirado na OP (disponível para devolver: ${availableToReturn}).`);
      }

      await client.query(`
          INSERT INTO op_returns (client_service_id, product_id, quantity, user_id, observation)
          VALUES ($1, $2, $3, $4, $5)
      `, [client_service_id, item.product_id, returnQty, userId, item.observation]);

      await client.query(`
          UPDATE stock
          SET quantity_on_hand = quantity_on_hand + $1
          WHERE product_id = $2
      `, [returnQty, item.product_id]);
    }

    await createLog(userId, 'OP_RETURN', { op_code, itemsReturned: returns.length }, getClientIp(req), client);

    await client.query('COMMIT'); 
    res.status(201).json({ success: true, message: 'Devolução registada com sucesso!' });

  } catch (error: any) {
    await client.query('ROLLBACK'); 
    console.error('Erro ao registar devolução:', error);
    res.status(400).json({ error: error.message || 'Erro ao processar devolução.' });
  } finally {
    client.release();
  }
};

// =========================================================================
// NOVO ENDPOINT: ENTRADA DE STOCK EM LOTE (USADO PELOS NOVOS PAINÉIS DE ENTRADA)
// =========================================================================

export const registerEntries = async (req: Request, res: Response) => {
  const { entries } = req.body;
  const userId = (req as any).user.id; 

  if (!entries || !Array.isArray(entries) || entries.length === 0) {
    return res.status(400).json({ error: 'Nenhuma entrada fornecida.' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. 🟢 MAGIA AQUI: Criamos o log de cabeçalho na tabela xml_logs para o Reports.tsx poder ler!
    const typeLabel = entries[0]?.type === 'REAPROVEITAMENTO' ? '♻️ Reaproveitamento' : '📦 Entrada NFe';
    
    // Gravamos com a data e hora para ficar perfeitamente alinhado na linha temporal do Dashboard
    const logRes = await client.query(
      "INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", 
      [`${typeLabel} - ${new Date().toLocaleString('pt-BR')}`, true, entries.length]
    );

    const logId = logRes.rows[0].id;

    await setStockAudit(
      client,
      entries[0]?.type === 'REAPROVEITAMENTO' ? 'ENTRADA_REAPROVEITAMENTO' : 'ENTRADA_NFE',
      userId,
      `entrada:${logId}`
    );

    for (const entry of entries) {
      const { product_id, quantity, type, observation } = entry;

      // 🛡️ CORREÇÃO 1: Tratar a quantidade para garantir que é sempre um número válido.
      // Se vier "20,00" do frontend, converte para 20.00
      const numericQty = typeof quantity === 'string' ? parseFloat(quantity.replace(',', '.')) : Number(quantity);

      if (!product_id || isNaN(numericQty) || numericQty <= 0) {
        throw new Error(`Item inválido: falta Produto ou a Quantidade (${quantity}) é inválida.`);
      }

      // Upsert atômico: elimina a corrida "UPDATE 0 linhas → INSERT" que podia
      // duplicar a linha de stock (ou abortar a transação) sob concorrência.
      await client.query(`
        INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved)
        VALUES ($1, $2::numeric, 0)
        ON CONFLICT (product_id)
        DO UPDATE SET quantity_on_hand = COALESCE(stock.quantity_on_hand, 0) + $2::numeric
      `, [product_id, numericQty]);

      // 3. 🟢 MAGIA AQUI: Inserimos o item na tabela xml_items, conectada ao log
      await client.query(
        "INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", 
        [logId, product_id, numericQty]
      );
    }

    // 4. Regista Log de Auditoria
    await createLog(userId, 'STOCK_ENTRY', { type: entries[0]?.type, totalItems: entries.length }, getClientIp(req), client);

    await client.query('COMMIT');

    // Notificações Push
    if ((req as any).io) {
      (req as any).io.to('compras').emit('new_request_notification', { 
        message: '📦 Nova Entrada/Reaproveitamento de Stock registada!', 
        action: 'Ver Estoque', 
        type: 'entrada' 
      });
    }

    res.status(201).json({ success: true, message: 'Entradas registadas com sucesso.' });
  } catch (error: any) {
    await client.query('ROLLBACK');
    console.error('Erro ao registar lote de entradas:', error);
    res.status(500).json({ error: error.message || 'Erro interno ao registar as entradas.' });
  } finally {
    client.release();
  }
};
