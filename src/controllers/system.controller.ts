import { Request, Response } from 'express';
import { pool } from '../db';

export const getDashboardStats = async (req: Request, res: Response) => {
  try {
    const query = `
      SELECT 
        (SELECT COUNT(*) FROM products WHERE active = true) as total_products,
        (SELECT COUNT(*) FROM products p LEFT JOIN stock s ON p.id = s.product_id WHERE p.min_stock IS NOT NULL AND (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) < CAST(NULLIF(CAST(p.min_stock AS TEXT), '') AS NUMERIC) AND p.active = true) as low_stock,
        (SELECT COUNT(*) FROM requests) as total_requests,
        (SELECT COUNT(*) FROM requests WHERE status = 'aberto') as open_requests,
        (SELECT COUNT(*) FROM separations WHERE type = 'op' OR type = 'default') as total_separations,
        (SELECT COALESCE(SUM(s.quantity_on_hand * CAST(NULLIF(CAST(p.unit_price AS TEXT), '') AS NUMERIC)), 0) FROM stock s JOIN products p ON s.product_id = p.id WHERE p.active = true) as total_value
    `;
    const { rows } = await pool.query(query);
    const s = rows[0];
    res.json({ totalProducts: parseInt(s.total_products || '0'), lowStock: parseInt(s.low_stock || '0'), totalRequests: parseInt(s.total_requests || '0'), openRequests: parseInt(s.open_requests || '0'), totalSeparations: parseInt(s.total_separations || '0'), totalValue: parseFloat(s.total_value || '0') });
  } catch (error: any) { res.status(500).json({ error: 'Erro stats' }); }
};

export const getManagerialReports = async (req: Request, res: Response) => {
  try {
    const topProductsQuery = `SELECT p.name, SUM(si.quantity) as total FROM separation_items si JOIN products p ON si.product_id = p.id JOIN separations s ON si.separation_id = s.id WHERE s.status = 'concluida' GROUP BY p.name ORDER BY total DESC LIMIT 5`;
    const historyQuery = `WITH months AS (SELECT generate_series(date_trunc('month', CURRENT_DATE) - INTERVAL '5 months', date_trunc('month', CURRENT_DATE), '1 month'::interval) as month) SELECT TO_CHAR(m.month, 'Mon') as name, COALESCE(SUM(xi.quantity), 0) as entradas, (SELECT COALESCE(SUM(si.quantity), 0) FROM separation_items si JOIN separations s ON si.separation_id = s.id WHERE date_trunc('month', s.created_at) = m.month AND s.status = 'concluida') as saidas FROM months m LEFT JOIN xml_logs xl ON date_trunc('month', xl.created_at) = m.month LEFT JOIN xml_items xi ON xi.xml_log_id = xl.id GROUP BY m.month ORDER BY m.month ASC`;
    const statusPieQuery = `SELECT COALESCE(purchase_status, 'pendente') as name, COUNT(*) as value FROM products WHERE active = true GROUP BY purchase_status`;

    const topProducts = await pool.query(topProductsQuery);
    const history = await pool.query(historyQuery);
    const statusPie = await pool.query(statusPieQuery);

    res.json({ topProducts: topProducts.rows, history: history.rows, purchaseStatus: statusPie.rows });
  } catch (error: any) { res.status(500).json({ error: 'Erro ao gerar dados gerenciais' }); }
};

export const getRecentTransactions = async (req: Request, res: Response) => {
  try {
    const query = `
      SELECT xi.id::text as id, 'in' as type, p.name as product_name, p.sku as product_sku, xi.quantity as amount, xi.created_at FROM xml_items xi JOIN products p ON xi.product_id = p.id
      UNION ALL SELECT si.id::text as id, 'out' as type, p.name as product_name, p.sku as product_sku, si.quantity as amount, s.created_at FROM separation_items si JOIN separations s ON si.separation_id = s.id JOIN products p ON si.product_id = p.id WHERE s.status = 'concluida'
      UNION ALL SELECT ri.id::text as id, 'out' as type, COALESCE(p.name, ri.custom_product_name) as product_name, p.sku as product_sku, ri.quantity_requested as amount, r.created_at FROM request_items ri JOIN requests r ON ri.request_id = r.id LEFT JOIN products p ON ri.product_id = p.id WHERE r.status IN ('aprovado', 'entregue')
      ORDER BY created_at DESC LIMIT 15;
    `;
    const { rows } = await pool.query(query);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: 'Erro ao buscar extrato' }); }
};

export const getAvailableDates = async (req: Request, res: Response) => {
  try {
    const result = await pool.query(`SELECT MIN(data) as min_date, MAX(data) as max_date FROM (SELECT created_at as data FROM xml_items UNION ALL SELECT created_at as data FROM separations WHERE status = 'concluida' UNION ALL SELECT created_at as data FROM requests WHERE status IN ('aprovado', 'entregue')) as all_dates`);
    res.json(result.rows[0]);
  } catch (error: any) { res.status(500).json({ error: 'Erro dates' }); }
};

export const getGeneralReports = async (req: Request, res: Response) => {
  const { startDate, endDate } = req.query;
  if (!startDate || !endDate) return res.status(400).json({ error: 'Datas obrigatórias' });
  const start = `${startDate} 00:00:00`; const end = `${endDate} 23:59:59`;
  try {
    const entradasRes = await pool.query(`SELECT xi.created_at as data, 'Entrada' as tipo, xl.file_name as origem, p.name as produto, p.sku, p.unit as unidade, xi.quantity as quantidade FROM xml_items xi JOIN products p ON xi.product_id = p.id JOIN xml_logs xl ON xi.xml_log_id = xl.id WHERE xi.created_at >= $1 AND xi.created_at <= $2 ORDER BY xi.created_at DESC`, [start, end]);
    const separacoesRes = await pool.query(`SELECT s.created_at as data, CASE WHEN s.type='manual' THEN 'Saída - Manual' ELSE 'Saída - Separação' END as tipo, s.destination as destino_setor, p.name as produto, p.sku, p.unit as unidade, si.quantity as quantidade, COALESCE(CAST(NULLIF(CAST(p.unit_price AS TEXT), '') AS NUMERIC), 0) as preco_unitario FROM separation_items si JOIN separations s ON si.separation_id = s.id JOIN products p ON si.product_id = p.id WHERE s.created_at >= $1 AND s.created_at <= $2 AND s.status = 'concluida' ORDER BY s.created_at DESC`, [start, end]);
    const solicitacoesRes = await pool.query(`SELECT r.created_at as data, 'Saída - Solicitação' as tipo, COALESCE(pf.sector, r.sector) as destino_setor, pf.name as solicitante, COALESCE(p.name, ri.custom_product_name) as produto, p.sku, p.unit as unidade, ri.quantity_requested as quantidade, r.status, COALESCE(CAST(NULLIF(CAST(p.unit_price AS TEXT), '') AS NUMERIC), 0) as preco_unitario FROM request_items ri JOIN requests r ON ri.request_id = r.id LEFT JOIN products p ON ri.product_id = p.id LEFT JOIN profiles pf ON r.requester_id = pf.id WHERE r.created_at >= $1 AND r.created_at <= $2 AND r.status IN ('aprovado', 'entregue') ORDER BY r.created_at DESC`, [start, end]);
    const estoqueRes = await pool.query(`SELECT p.name as produto, p.sku, COALESCE(CAST(NULLIF(CAST(s.quantity_on_hand AS TEXT), '') AS NUMERIC), 0) as quantidade, COALESCE(CAST(NULLIF(CAST(p.unit_price AS TEXT), '') AS NUMERIC), 0) as preco, COALESCE(CAST(NULLIF(CAST(p.min_stock AS TEXT), '') AS NUMERIC), 0) as estoque_minimo, GREATEST((SELECT MAX(created_at)::timestamp FROM xml_items WHERE product_id = p.id), (SELECT MAX(sep.created_at)::timestamp FROM separation_items si JOIN separations sep ON si.separation_id = sep.id WHERE sep.status = 'concluida' AND si.product_id = p.id), (SELECT MAX(r.created_at)::timestamp FROM request_items ri JOIN requests r ON ri.request_id = r.id WHERE r.status IN ('aprovado', 'entregue') AND ri.product_id = p.id)) as ultima_movimentacao FROM stock s JOIN products p ON s.product_id = p.id WHERE p.active = true`);
    const comparativoRes = await pool.query(`SELECT (SELECT COUNT(*) FROM xml_items xi WHERE xi.created_at >= $1::timestamp - INTERVAL '1 month' AND xi.created_at <= $2::timestamp - INTERVAL '1 month') as entradas_ant, ((SELECT COUNT(*) FROM separation_items si JOIN separations sep ON si.separation_id = sep.id WHERE sep.created_at >= $1::timestamp - INTERVAL '1 month' AND sep.created_at <= $2::timestamp - INTERVAL '1 month' AND sep.status = 'concluida') + (SELECT COUNT(*) FROM request_items ri JOIN requests req ON ri.request_id = req.id WHERE req.created_at >= $1::timestamp - INTERVAL '1 month' AND req.created_at <= $2::timestamp - INTERVAL '1 month' AND req.status IN ('aprovado', 'entregue'))) as saidas_ant`, [start, end]);
    res.json({ entradas: entradasRes.rows, saidas_separacoes: separacoesRes.rows, saidas_solicitacoes: solicitacoesRes.rows, estoque: estoqueRes.rows, comparativo_mes_anterior: { entradas: parseInt(comparativoRes.rows[0].entradas_ant || 0), saidas: parseInt(comparativoRes.rows[0].saidas_ant || 0) } });
  } catch (error: any) { res.status(500).json({ error: 'Erro relatório general: ' + error.message }); }
};

export const getAdminLogs = async (req: Request, res: Response) => {
  const requesterId = (req as any).user.id;
  try {
    const adminCheck = await pool.query("SELECT role FROM profiles WHERE id = $1", [requesterId]);
    if (adminCheck.rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Acesso negado.' });

    const { action, user, startDate, endDate } = req.query;
    let query = `
      SELECT a.id, a.action, a.details, a.created_at, a.ip_address, COALESCE(p.name, u.email, 'Usuário Removido') as user_name, COALESCE(p.role::text, 'removido') as user_role
      FROM audit_logs a LEFT JOIN users u ON a.user_id = u.id LEFT JOIN profiles p ON u.id = p.id WHERE 1=1
    `;
    const params: any[] = [];
    let paramIndex = 1;

    if (action && action !== 'ALL') { query += ` AND a.action = $${paramIndex}`; params.push(action); paramIndex++; }
    if (user) { query += ` AND (p.name ILIKE $${paramIndex} OR u.email ILIKE $${paramIndex})`; params.push(`%${user}%`); paramIndex++; }
    if (startDate) { query += ` AND a.created_at >= $${paramIndex}`; params.push(`${startDate} 00:00:00`); paramIndex++; }
    if (endDate) { query += ` AND a.created_at <= $${paramIndex}`; params.push(`${endDate} 23:59:59`); paramIndex++; }

    query += ` ORDER BY a.created_at DESC LIMIT 100`;
    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (error: any) { res.status(500).json({ error: "Erro ao buscar logs" }); }
};
