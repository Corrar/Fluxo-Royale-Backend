import { Request, Response } from 'express';
import { pool } from '../db';

// 1. Buscar todos os clientes com as suas OPs
export const getClients = async (req: Request, res: Response) => {
  try {
    const clientsQuery = `
        SELECT c.*, 
               COALESCE(
                 json_agg(
                   json_build_object('id', s.id, 'op_code', s.op_code, 'description', s.description)
                 ) FILTER (WHERE s.id IS NOT NULL), '[]'
               ) as services
        FROM clients c
        LEFT JOIN client_services s ON c.id = s.client_id
        GROUP BY c.id
        ORDER BY c.name ASC
    `;
    const result = await pool.query(clientsQuery);
    res.json(result.rows);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};

// 2. Criar um novo cliente
export const createClient = async (req: Request, res: Response) => {
  try {
    const { code, name } = req.body;
    
    if (!code || !name) {
      return res.status(400).json({ error: 'Código e Nome são obrigatórios.' });
    }

    const query = `
      INSERT INTO clients (code, name) 
      VALUES ($1, $2) 
      RETURNING *
    `;
    const result = await pool.query(query, [code, name]);
    
    res.status(201).json(result.rows[0]);
  } catch (error: any) {
    if (error.code === '23505') { // Erro de violação de chave única no Postgres
        return res.status(400).json({ error: 'Já existe um cliente com este código.' });
    }
    res.status(500).json({ error: error.message });
  }
};

// 3. Adicionar uma nova OP a um cliente
export const createService = async (req: Request, res: Response) => {
  try {
    const { id } = req.params; // ID do cliente
    const { op_code, description } = req.body;

    if (!op_code) {
      return res.status(400).json({ error: 'O código da OP é obrigatório.' });
    }

    const query = `
      INSERT INTO client_services (client_id, op_code, description) 
      VALUES ($1, $2, $3) 
      RETURNING *
    `;
    const result = await pool.query(query, [id, op_code, description]);
    
    res.status(201).json(result.rows[0]);
  } catch (error: any) {
    if (error.code === '23505') {
        return res.status(400).json({ error: 'Esta OP já está registrada.' });
    }
    res.status(500).json({ error: error.message });
  }
};
