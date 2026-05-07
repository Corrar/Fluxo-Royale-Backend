import { Request, Response } from 'express';
import { pool } from '../db'; 
import { getClientIp } from '../utils/ip';
import { createLog } from '../utils/logger';

// 🧠 SANITIZADOR DE TAGS BLINDADO
// Limpa os objetos do TagInput e extrai apenas o texto puro (String).
const sanitizeTags = (tagsData: any): { is3D: boolean, parsed: string[] } => {
  let rawArray: any[] = [];
  
  if (!tagsData) return { is3D: false, parsed: [] };

  if (Array.isArray(tagsData)) {
    rawArray = tagsData;
  } else if (typeof tagsData === 'string') {
    try { 
      rawArray = JSON.parse(tagsData); 
      if (!Array.isArray(rawArray)) rawArray = [tagsData];
    } catch (e) { 
      rawArray = tagsData.split(',').map((s: string) => s.trim()); 
    }
  }

  // 🛡️ Filtra e extrai apenas strings puras para evitar erros no React
  const stringTags = rawArray
    .filter(t => t !== null && t !== undefined && t !== "")
    .map(t => {
       if (typeof t === 'object' && t.name) return String(t.name).trim();
       if (typeof t === 'object') return 'Tag';
       return String(t).trim();
    });

  const is3D = stringTags.some(t => t.toLowerCase() === '3d');

  return { is3D, parsed: stringTags };
};

export const getProducts = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.sku, p.name, p.description, p.unit, p.tags, p.unit_price, p.sales_price, p.min_stock, p.active,
        p.is_3d, p.production_minutes, p.filament_grams, p.image_url,
        json_build_object('quantity_on_hand', COALESCE(s.quantity_on_hand, 0), 'quantity_reserved', COALESCE(s.quantity_reserved, 0)) as stock
      FROM products p LEFT JOIN stock s ON p.id = s.product_id WHERE p.active = true ORDER BY p.name ASC
    `);
    
    // 🛡️ A CORREÇÃO MÁGICA AQUI:
    // Nós limpamos a sujeira e devolvemos exatamente em formato de Texto (JSON.stringify)
    // Isso evita o erro de "0 produtos" no Products.tsx
    const safeRows = rows.map(r => {
       const { parsed } = sanitizeTags(r.tags);
       return { ...r, tags: JSON.stringify(parsed) }; 
    });

    res.json(safeRows);
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
    
    const safeRows = rows.map(r => {
       const { parsed } = sanitizeTags(r.tags);
       return { ...r, tags: JSON.stringify(parsed) }; 
    });

    res.json(safeRows);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar estoque baixo' }); }
};

export const createProduct = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price, tags, is_3d, production_minutes, filament_grams, image_url } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const skuCheck = await client.query('SELECT id, active FROM products WHERE sku = $1', [sku]);
    
    if (skuCheck.rows.length > 0) {
      const existingProduct = skuCheck.rows[0];
      if (existingProduct.active) {
        throw new Error('Já existe um produto ativo cadastrado com este SKU.');
      } else {
        throw new Error('Este SKU já pertence a um produto que foi arquivado (inativo). Por favor, reative-o ou utilize um código diferente.');
      }
    }

    // 🚀 Usa o Sanitizador na entrada de dados
    const { is3D: detected3D, parsed: parsedTags } = sanitizeTags(tags);
    const finalIs3D = is_3d || detected3D;

    const productRes = await client.query(
      `INSERT INTO products (sku, name, description, unit, min_stock, unit_price, sales_price, tags, is_3d, production_minutes, filament_grams, image_url) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12) RETURNING *`,
      [
        sku, name, description, unit, min_stock, unit_price || 0, sales_price || 0, JSON.stringify(parsedTags), 
        finalIs3D, production_minutes || 0, filament_grams || 0, image_url || null
      ]
    );
    const newProduct = productRes.rows[0];

    const initialQty = quantity ? parseFloat(quantity) : 0;
    await client.query(`INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved) VALUES ($1, $2, 0) ON CONFLICT (product_id) DO UPDATE SET quantity_on_hand = COALESCE(stock.quantity_on_hand, 0) + EXCLUDED.quantity_on_hand`, [newProduct.id, initialQty]);

    if (initialQty > 0) {
      const logRes = await client.query("INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", ['Estoque Inicial - Cadastro', true, 1]);
      await client.query("INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", [logRes.rows[0].id, newProduct.id, initialQty]);
    }
    
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
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price, tags, is_3d, production_minutes, filament_grams, image_url } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');

    let finalIs3D = is_3d;
    let finalTagsForDB = tags ? (typeof tags === 'string' ? tags : JSON.stringify(tags)) : null;

    if (tags !== undefined) {
      const { is3D: detected3D, parsed: parsedTags } = sanitizeTags(tags);
      finalIs3D = is_3d !== undefined ? is_3d : detected3D;
      if (detected3D) finalIs3D = true; 
      finalTagsForDB = JSON.stringify(parsedTags);
    }

    const { rows } = await client.query(
      `UPDATE products 
       SET sku = COALESCE($1, sku), name = COALESCE($2, name), description = COALESCE($3, description), 
           unit = COALESCE($4, unit), min_stock = COALESCE($5, min_stock), unit_price = COALESCE($6, unit_price), 
           sales_price = COALESCE($7, sales_price), tags = COALESCE($8, tags),
           is_3d = COALESCE($9, is_3d), production_minutes = COALESCE($10, production_minutes), 
           filament_grams = COALESCE($11, filament_grams), image_url = COALESCE($12, image_url)
       WHERE id = $13 RETURNING *`,
      [
        sku || null, name || null, description || null, unit || null, min_stock || null, unit_price || null, sales_price || null, finalTagsForDB,
        finalIs3D !== undefined ? finalIs3D : null, 
        production_minutes !== undefined ? production_minutes : null, 
        filament_grams !== undefined ? filament_grams : null, 
        image_url || null, 
        id
      ]
    );
    
    if (rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Produto não encontrado' }); }
    if (quantity !== undefined && quantity !== "") { await client.query('UPDATE stock SET quantity_on_hand = $1 WHERE product_id = $2', [parseFloat(quantity), id]); }
    
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
    await createLog(userId, 'ARQUIVAR_PRODUTO', { id_produto: id, mensagem: 'Produto movido para a lista de inativos' }, getClientIp(req));
    res.json({ message: 'Produto arquivado com sucesso' });
  } catch (error: any) { res.status(500).json({ error: error.message }); }
};

export const updatePurchaseInfo = async (req: Request, res: Response) => {
  const { id } = req.params;
  const { purchase_status, purchase_note, delivery_forecast } = req.body;
  try {
    await pool.query('UPDATE products SET purchase_status = $1, purchase_note = $2, delivery_forecast = $3 WHERE id = $4', [purchase_status, purchase_note, delivery_forecast || null, id]);
    const userId = (req as any).user?.id || null;
    await createLog(userId, 'ATUALIZAR_INFO_COMPRA', { id_produto: id, status: purchase_status, previsao: delivery_forecast }, getClientIp(req));
    res.json({ success: true });
  } catch (error: any) { res.status(500).json({ error: 'Erro ao atualizar info de compra' }); }
};

export const reactivateProduct = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { sku } = req.params; 
  try {
    const { rows } = await pool.query('UPDATE products SET active = true WHERE sku = $1 RETURNING *', [sku]);
    if (rows.length === 0) return res.status(404).json({ error: 'Nenhum produto encontrado com este SKU para reativar.' });
    await createLog(userId, 'REATIVAR_PRODUTO', { sku, mensagem: 'Produto retirado da lista de inativos' }, getClientIp(req));
    res.json({ message: 'Produto reativado com sucesso!', product: rows[0] });
  } catch (error: any) { res.status(500).json({ error: error.message }); }
};

export const getInactiveProducts = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT p.id, p.sku, p.name, p.description, p.unit, p.unit_price, p.active,
        p.is_3d, p.production_minutes, p.filament_grams, p.image_url,
        json_build_object('quantity_on_hand', COALESCE(s.quantity_on_hand, 0)) as stock
      FROM products p LEFT JOIN stock s ON p.id = s.product_id 
      WHERE p.active = false ORDER BY p.name ASC
    `);
    
    const safeRows = rows.map(r => {
       const { parsed } = sanitizeTags(r.tags);
       return { ...r, tags: JSON.stringify(parsed) }; 
    });

    res.json(safeRows);
  } catch (error: any) { res.status(500).json({ error: error.message }); }
};

export const updateProductPrices = async (req: Request, res: Response) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  const { unit_price, sales_price } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const { rows } = await client.query(
      `UPDATE products SET unit_price = COALESCE($1, unit_price), sales_price = COALESCE($2, sales_price) WHERE id = $3 RETURNING *`,
      [unit_price, sales_price, id]
    );
    if (rows.length === 0) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Produto não encontrado' }); }
    await createLog(userId, 'ATUALIZAR_PRECOS', { id_produto: id, novos_precos: { unit_price, sales_price } }, getClientIp(req), client);
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
};
