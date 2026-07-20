import { pool } from '../db';
import { createLog } from '../utils/logger';

export const startExpireRequestsJob = () => {
  setInterval(async () => {
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      const { rows: expiredRequests } = await client.query(`
        SELECT id FROM requests
        WHERE status IN ('aberto', 'aprovado')
        AND created_at < NOW() - INTERVAL '15 days'
        FOR UPDATE SKIP LOCKED
      `);

      for (const req of expiredRequests) {
         // Usa a quantidade ajustada (delivered) quando existir e trata itens 3D:
         // para 3D só foi reservado o que havia em prateleira (o resto ficou no
         // Kanban), então libertar o pedido inteiro roubava reserva de outros pedidos.
         const itemsRes = await client.query(`
           SELECT ri.product_id, ri.quantity_requested, ri.quantity_delivered, p.is_3d
           FROM request_items ri LEFT JOIN products p ON ri.product_id = p.id
           WHERE ri.request_id = $1 ORDER BY ri.product_id
         `, [req.id]);

         for (const item of itemsRes.rows) {
           if (!item.product_id) continue;

           let releaseQty: number;
           if (item.is_3d) {
             const dem = await client.query(
               `SELECT COALESCE(SUM(quantity), 0) as pending FROM demands_3d WHERE request_id = $1 AND product_id = $2 AND status != 'Concluída'`,
               [req.id, item.product_id]
             );
             releaseQty = Math.max(0, parseFloat(item.quantity_requested) - parseFloat(dem.rows[0].pending));
           } else {
             releaseQty = parseFloat(item.quantity_delivered ?? item.quantity_requested);
           }

           if (releaseQty > 0) {
             await client.query(`
               UPDATE stock SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1) WHERE product_id = $2
             `, [releaseQty, item.product_id]);
           }
         }

         await client.query(`UPDATE requests SET status = 'rejeitado', rejection_reason = 'Expirado pelo sistema (Timeout 15 dias)' WHERE id = $1`, [req.id]);
         // Cancela as demandas 3D pendentes para a produção não fabricar material de pedido morto
         await client.query(`UPDATE demands_3d SET status = 'Cancelada' WHERE request_id = $1 AND status NOT IN ('Concluída', 'Cancelada')`, [req.id]);
         // Nota: usamos '127.0.0.1' porque é o próprio servidor a fazer a ação
         await createLog(null, 'TIMEOUT_REQUEST', { requestId: req.id, reason: 'Expiração automática' }, '127.0.0.1', client);
      }
      await client.query('COMMIT');
      if (expiredRequests.length > 0) console.log(`🧹 Cron: ${expiredRequests.length} reservas expiradas e libertadas.`);
    } catch (error) {
      await client.query('ROLLBACK');
      console.error("Erro no Cron de Expiração:", error);
    } finally {
      client.release();
    }
  }, 1000 * 60 * 60 * 24); // Executa a cada 24 horas

  console.log("⏳ Cron Job de expiração de reservas inicializado.");
};
