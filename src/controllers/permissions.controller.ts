import { Request, Response } from 'express';
import { pool } from '../db';
import { createLog } from '../utils/logger';
import { getClientIp } from '../utils/ip';

export const getPermissions = async (req: Request, res: Response) => {
  try {
    const { rows } = await pool.query('SELECT role, page_key FROM role_permissions');
    const permissionsMap: Record<string, string[]> = {};
    
    rows.forEach((row: any) => {
      if (!permissionsMap[row.role]) {
        permissionsMap[row.role] = [];
      }
      permissionsMap[row.role].push(row.page_key);
    });
    
    res.json(permissionsMap);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar permissões' });
  }
};

export const updatePermissions = async (req: Request, res: Response) => {
  const { role, permissions } = req.body;
  const requesterId = (req as any).user.id;
  
  // 🛡️ Proteção: Apenas Admins podem alterar permissões
  const adminCheck = await pool.query("SELECT role FROM profiles WHERE id = $1", [requesterId]);
  if (adminCheck.rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Apenas admins.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    // Limpa as permissões antigas do cargo e insere as novas
    await client.query('DELETE FROM role_permissions WHERE role = $1', [role]);
    for (const page of permissions) {
      await client.query('INSERT INTO role_permissions (role, page_key) VALUES ($1, $2)', [role, page]);
    }
    
    // 📝 Log de Auditoria
    await createLog(requesterId, 'UPDATE_PERMISSIONS', { role_target: role, count: permissions.length }, getClientIp(req), client);
    
    await client.query('COMMIT');
    
    // ⚡ Atualiza o Frontend em tempo real
    if ((req as any).io) {
        (req as any).io.to(role).emit('permissions_updated', permissions);
    }

    res.json({ success: true });
  } catch (error: any) {
    try { await client.query('ROLLBACK'); } catch(e) {}
    res.status(500).json({ error: 'Erro ao salvar permissões' });
  } finally {
    client.release();
  }
};
