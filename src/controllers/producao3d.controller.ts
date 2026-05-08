import { Request, Response } from 'express';
import { pool } from '../db';

// ==========================================
// 1. CATÁLOGO DE PEÇAS 3D (Lê da tabela Products)
// ==========================================
export const get3DParts = async (req: Request, res: Response) => {
  try {
    // Busca apenas os produtos marcados como 3D na tabela principal
    const { rows } = await pool.query(`
        SELECT id, code, name, image_url as image, production_minutes, filament_grams, category as material, description 
        FROM products 
        WHERE is_3d = true 
        ORDER BY name ASC
    `);
    
    // Formata os nomes das variáveis para o frontend entender (camelCase)
    const formatted = rows.map(r => ({
       id: r.id, code: r.code, name: r.name, image: r.image, 
       productionMinutes: r.production_minutes, filamentGrams: r.filament_grams, 
       material: r.material, description: r.description
    }));
    
    res.json(formatted);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar catálogo 3D' });
  }
};

// Quando o operador 3D preenche o tempo e o filamento no catálogo
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
    // Busca as demandas e junta com o nome de quem pediu na tabela requests original
    // CORRIGIDO: r.user_id alterado para r.requester_id
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
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // Atualiza o cartão no Kanban
    await client.query('UPDATE demands_3d SET status = $1 WHERE id = $2', [status, id]);

    // SE A PEÇA FOI CONCLUÍDA, A MÁGICA DE ESTOQUE ACONTECE:
    if (status === 'Concluída') {
        const demandRes = await client.query('SELECT request_id, quantity, product_id FROM demands_3d WHERE id = $1', [id]);
        const demand = demandRes.rows[0];

        if (demand.product_id) {
            // 1. Dá entrada no estoque FÍSICO da peça produzida e reserva-a imediatamente para o pedido
            await client.query(
                `UPDATE stock 
                 SET quantity_on_hand = COALESCE(quantity_on_hand, 0) + $1,
                     quantity_reserved = COALESCE(quantity_reserved, 0) + $1
                 WHERE product_id = $2`,
                [demand.quantity, demand.product_id]
            );

            // 2. Registra no histórico de movimentações (Extrato)
            await client.query(
                `INSERT INTO stock_transactions (product_id, quantity, type, user_id, reason) 
                 VALUES ($1, $2, 'ENTRADA', $3, 'Produção 3D Concluída')`,
                [demand.product_id, demand.quantity, (req as any).user.id]
            );
        }

        // 3. Muda o status da solicitação original do setor para "aprovado" (Pronta para Retirada no Almoxarifado)
        if (demand.request_id) {
            await client.query(`UPDATE requests SET status = 'aprovado' WHERE id = $1`, [demand.request_id]);
        }
    }
    
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao mover demanda no Kanban' });
  } finally {
    client.release();
  }
};

// ==========================================
// 3. HISTÓRICO E REGISTO DE PRODUÇÃO
// ==========================================

export const getProductions = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query(`
      SELECT id, product_id as "partId", demand_id as "demandId", quantity, 
             total_minutes as "totalMinutes", filament_grams as "filamentGrams", 
             date, operator_id as operator 
      FROM productions_3d ORDER BY date ASC
    `);
    res.json(rows);
  } catch (error) {
    res.status(500).json({ error: 'Erro ao buscar produções' });
  }
};

export const createProduction = async (req: Request, res: Response) => {
  const { partId, demandId, quantity, operator, totalMinutes, filamentGrams, date } = req.body;
  
  try {
    const { rows } = await pool.query(`
        INSERT INTO productions_3d 
        (product_id, demand_id, quantity, operator_id, total_minutes, filament_grams, date)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
        RETURNING id, product_id as "partId", demand_id as "demandId", quantity, 
                  total_minutes as "totalMinutes", filament_grams as "filamentGrams", 
                  date, operator_id as operator
    `, [partId, demandId || null, quantity, operator, totalMinutes, filamentGrams, date]);
    
    res.status(201).json(rows[0]);
  } catch (error) {
    console.error('Erro ao criar produção:', error);
    res.status(500).json({ error: 'Erro ao registar produção 3D' });
  }
};

export const deleteProduction = async (req: Request, res: Response) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM productions_3d WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (error) {
    console.error('Erro ao apagar produção:', error);
    res.status(500).json({ error: 'Erro ao apagar produção 3D' });
  }
};
