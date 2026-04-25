import { Request, Response } from 'express';
import { supabase } from '../db';

// 1. Buscar todos os clientes com as suas OPs
export const getClients = async (req: Request, res: Response) => {
  try {
    const { data, error } = await supabase
      .from('clients')
      .select('*, services:client_services(*)');

    if (error) throw error;
    res.json(data);
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

    const { data, error } = await supabase
      .from('clients')
      .insert([{ code, name }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (error: any) {
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

    const { data, error } = await supabase
      .from('client_services')
      .insert([{ client_id: id, op_code, description }])
      .select()
      .single();

    if (error) throw error;
    res.status(201).json(data);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
};
