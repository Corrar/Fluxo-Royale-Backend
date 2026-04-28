import { Request, Response } from 'express';
import { pool } from '../db';

export const getClients = async (req: Request, res: Response) => {
  try {
    const clientsQuery = `
        SELECT c.*, 
               COALESCE(
                 json_agg(
                   json_build_object(
                     'id', s.id, 
                     'op_code', s.op_code, 
                     'description', s.description, 
                     'status', s.status
                   )
                 ) FILTER (WHERE s.id IS NOT NULL), '[]'::json
               ) as services
        FROM clients c
        LEFT JOIN client_services s ON c.id = s.client_id
        GROUP BY c.id
        ORDER BY c.created_at DESC
    `;
    const result = await pool.query(clientsQuery);
    res.json(result.rows);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};

export const createClient = async (req: Request, res: Response) => {
  try {
    const { code, name } = req.body;
    if (!code || !name) return res.status(400).json({ error: 'Código e Nome são obrigatórios.' });
    const query = `INSERT INTO clients (code, name) VALUES ($1, $2) RETURNING *`;
    const result = await pool.query(query, [code, name]);
    res.status(201).json(result.rows[0]);
  } catch (error: any) {
    if (error.code === '23505') return res.status(400).json({ error: 'Já existe um cliente com este código.' });
    res.status(500).json({ error: error.message });
  }
};

export const updateClient = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'O novo nome é obrigatório.' });
    const query = `UPDATE clients SET name = $1 WHERE id = $2 RETURNING *`;
    const result = await pool.query(query, [name, id]);
    res.json(result.rows[0]);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};

export const deleteClient = async (req: Request, res: Response) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Tenta primeiro apagar as OPs filhas que estejam "vazias"
    // Se a OP já foi usada no sistema, o erro 23503 é disparado aqui e o processo é interrompido em segurança.
    await client.query('DELETE FROM client_services WHERE client_id = $1', [req.params.id]);
    
    // Apaga o cliente
    await client.query('DELETE FROM clients WHERE id = $1', [req.params.id]);
    
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    // Captura o erro de chave estrangeira de forma amigável
    if (error.code === '23503') {
      return res.status(400).json({ error: 'Ação bloqueada: Não podes excluir este cliente, pois já existem peças movimentadas para uma de suas OPs.' });
    }
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
};

export const createService = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { op_code, description } = req.body;
    if (!op_code) return res.status(400).json({ error: 'O código da OP é obrigatório.' });
    const query = `INSERT INTO client_services (client_id, op_code, description) VALUES ($1, $2, $3) RETURNING *`;
    const result = await pool.query(query, [id, op_code, description]);
    res.status(201).json(result.rows[0]);
  } catch (error: any) {
    if (error.code === '23505') return res.status(400).json({ error: 'Esta OP já está registrada.' });
    res.status(500).json({ error: error.message });
  }
};

export const updateServiceStatus = async (req: Request, res: Response) => {
  try {
    const { serviceId } = req.params;
    let { status } = req.body;

    // Correção: Transforma o texto que vem do Frontend para o padrão esperado no Banco de Dados
    if (status === 'finalizada' || status === 'done') status = 'concluido';
    if (status === 'progress') status = 'em_andamento';

    await pool.query('UPDATE client_services SET status = $1 WHERE id = $2', [status, serviceId]);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao atualizar o status da OP: ' + error.message });
  }
};

export const deleteService = async (req: Request, res: Response) => {
  try {
    await pool.query('DELETE FROM client_services WHERE id = $1', [req.params.serviceId]);
    res.json({ success: true });
  } catch (error: any) {
    // Retorna erro amigável se a OP já tiver itens movimentados no sistema
    if (error.code === '23503') {
      return res.status(400).json({ error: 'Ação bloqueada: Já existem movimentações de estoque associadas a esta OP. Não podes apagá-la.' });
    }
    res.status(500).json({ error: error.message });
  }
};
