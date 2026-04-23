import { Request, Response } from 'express';
import { pool } from '../db'; 
import { getClientIp } from '../utils/ip';
import { createLog } from '../utils/logger';

export const getProducts = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.sku, p.name, p.description, p.unit, p.tags, p.unit_price, p.sales_price, p.min_stock, p.active,
        json_build_object('quantity_on_hand', COALESCE(s.quantity_on_hand, 0), 'quantity_reserved', COALESCE(s.quantity_reserved, 0)) as stock
      FROM products p LEFT JOIN stock s ON p.id = s.product_id WHERE p.active = true ORDER BY p.name ASC
    `);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
};

export const getLowStockProducts = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.sku, p.name, p.unit, p.min_stock, p.purchase_status, p.purchase_note, p.delivery_forecast, COALESCE(s.quantity_on_hand, 0) as quantity, COALESCE(s.quantity_reserved, 0) as quantity_reserved, s.critical_since, (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) as disponivel,
        (SELECT COALESCE(SUM(ri.quantity_requested), 0) FROM request_items ri JOIN requests r ON ri.request_id = r.id WHERE ri.product_id = p.id AND r.status IN ('aberto', 'aprovado')) as demanda_reprimida
      FROM products p LEFT JOIN stock s ON p.id = s.product_id
      WHERE p.active = true AND (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) <= COALESCE(CAST(NULLIF(CAST(p.min_stock AS TEXT), '') AS NUMERIC), 0) ORDER BY (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) ASC
    `);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar estoque baixo' }); }
};

export const createProduct = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price, tags } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 🛡️ Validação de Unicidade Ajustada
    // Procura o SKU na base de dados, independentemente de estar ativo ou não
    const skuCheck = await client.query('SELECT id, active FROM products WHERE sku = $1', [sku]);
    
    if (skuCheck.rows.length > 0) {
      const existingProduct = skuCheck.rows[0];
      if (existingProduct.active) {
        throw new Error('Já existe um produto ativo cadastrado com este SKU.');
      } else {
        throw new Error('Este SKU já pertence a um produto que foi arquivado (inativo). Por favor, reative-o ou utilize um código diferente.');
      }
    }

    // Criação do produto caso o SKU não exista
    const productRes = await client.query(
      'INSERT INTO products (sku, name, description, unit, min_stock, unit_price, sales_price, tags) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [sku, name, description, unit, min_stock, unit_price || 0, sales_price || 0, JSON.stringify(tags || [])]
    );
    const newProduct = productRes.rows[0];

    // Inserção da quantidade inicial no stock
    const initialQty = quantity ? parseFloat(quantity) : 0;
    await client.query(`INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved) VALUES ($1, $2, 0) ON CONFLICT (product_id) DO UPDATE SET quantity_on_hand = COALESCE(stock.quantity_on_hand, 0) + EXCLUDED.quantity_on_hand`, [newProduct.id, initialQty]);

    // Registo de logs se houver quantidade inicial
    if (initialQty > 0) {
      const logRes = await client.query("INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", ['Estoque Inicial - Cadastro', true, 1]);
      await client.query("INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", [logRes.rows[0].id, newProduct.id, initialQty]);
    }
    
    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'CRIAR_PRODUTO', { sku, name, quantidade_inicial: initialQty }, getClientIp(req), client);
    await client.query('COMMIT');
    res.status(201).json(newProduct);
    
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(400).json({ error: error.message });
  } finally { 
    client.release(); 
  }
};

export const updateProduct = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price, tags } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE products SET sku = COALESCE($1, sku), name = COALESCE($2, name), description = COALESCE($3, description), unit = COALESCE($4, unit), min_stock = COALESCE($5, min_stock), unit_price = COALESCE($6, unit_price), sales_price = COALESCE($7, sales_price), tags = COALESCE($8, tags) WHERE id = $9 RETURNING *`,
      [sku || null, name || null, description || null, unit || null, min_stock || null, unit_price || null, sales_price || null, tags ? JSON.stringify(tags) : null, id]
    );
    if (rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Produto não encontrado' }); }
    if (quantity !== undefined && quantity !== "") { await client.query('UPDATE stock SET quantity_on_hand = $1 WHERE product_id = $2', [parseFloat(quantity), id]); }
    
    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'EDITAR_PRODUTO', { id_produto: id, nome: name, alteracoes: req.body }, getClientIp(req), client);
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
};

export const deleteProduct = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  try {
    await pool.query('UPDATE products SET active = false WHERE id = $1', [id]);
    
    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'ARQUIVAR_PRODUTO', { id_produto: id, mensagem: 'Produto movido para a lista de inativos' }, getClientIp(req));
    res.json({ message: 'Produto arquivado com sucesso' });
  } catch (error: any) { res.status(500).json({ error: error.message }); }
};

export const updatePurchaseInfo = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { purchase_status, purchase_note, delivery_forecast } = req.body;
  try {
    await pool.query('UPDATE products SET purchase_status = $1, purchase_note = $2, delivery_forecast = $3 WHERE id = $4', [purchase_status, purchase_note, delivery_forecast || null, id]);
    
    // 📝 NOVO LOG DE AUDITORIA ADICIONADO
    const userId = (req as any).user?.id || null;
    await createLog(userId, 'ATUALIZAR_INFO_COMPRA', { id_produto: id, status: purchase_status, previsao: delivery_forecast }, getClientIp(req));
    
    res.json({ success: true });
  } catch (error: any) { res.status(500).json({ error: 'Erro ao atualizar info de compra' }); }
};

// ♻️ Nova função para reativar produtos arquivados (fantasmas)
export const reactivateProduct = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { sku } = req.params; 
  
  try {
    const { rows } = await pool.query(
      'UPDATE products SET active = true WHERE sku = $1 RETURNING *',
      [sku]
    );

    if (rows.length === 0) {
      return res.status(404).json({ error: 'Nenhum produto encontrado com este SKU para reativar.' });
    }

    // 📝 LOG TRADUZIDO E MELHORADO
    await createLog(userId, 'REATIVAR_PRODUTO', { sku, mensagem: 'Produto retirado da lista de inativos' }, getClientIp(req));
    res.json({ message: 'Produto reativado com sucesso!', product: rows[0] });
    
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};

// 🗑️ Nova função para listar produtos arquivados (inativos)
export const getInactiveProducts = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.sku, p.name, p.description, p.unit, p.unit_price, p.active,
        json_build_object('quantity_on_hand', COALESCE(s.quantity_on_hand, 0)) as stock
      FROM products p LEFT JOIN stock s ON p.id = s.product_id 
      WHERE p.active = false 
      ORDER BY p.name ASC
    `);
    res.json(rows);
  } catch (error: any) { 
    res.status(500).json({ error: error.message }); 
  }
};

// 💰 NOVA FUNÇÃO: Atualizar APENAS os preços (Para o setor financeiro)
export const updateProductPrices = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  
  // Extraímos apenas os preços do corpo do pedido. Ignoramos tudo o resto.
  const { unit_price, sales_price } = req.body;
  
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Atualiza apenas os preços. O COALESCE mantém o valor antigo se não for enviado nenhum novo.
    const { rows } = await client.query(
      `UPDATE products 
       SET unit_price = COALESCE($1, unit_price), 
           sales_price = COALESCE($2, sales_price) 
       WHERE id = $3 RETURNING *`,
      [unit_price, sales_price, id]
    );

    if (rows.length === 0) { 
      await client.query('ROLLBACK'); 
      return res.status(404).json({ error: 'Produto não encontrado' }); 
    }
    
    // 📝 LOG DE AUDITORIA
    await createLog(
      userId, 
      'ATUALIZAR_PRECOS', 
      { id_produto: id, novos_precos: { unit_price, sales_price } }, 
      getClientIp(req), 
      client
    );
    
    await client.query('COMMIT');
    res.json(rows[0]);
    
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { 
    client.release(); 
  }
};
