import webpush from 'web-push';
import { pool } from '../db';

export const sendPushNotificationToRole = async (role: string, title: string, message: string, url: string = '/requests', uniqueId?: string) => {
  try {
    let query = `
      SELECT ps.subscription 
      FROM push_subscriptions ps
      JOIN profiles p ON ps.user_id::uuid = p.id
      WHERE p.role = $1
    `;
    let params: any[] = [role];
    
    if (role === 'almoxarife') {
       query = `SELECT ps.subscription FROM push_subscriptions ps JOIN profiles p ON ps.user_id::uuid = p.id WHERE p.role IN ('almoxarife', 'admin')`;
       params = [];
    } else if (role === 'compras') {
       query = `SELECT ps.subscription FROM push_subscriptions ps JOIN profiles p ON ps.user_id::uuid = p.id WHERE p.role IN ('compras', 'admin')`;
       params = [];
    }

    const { rows } = await pool.query(query, params);
    if (rows.length === 0) return;

    const notificationTag = uniqueId ? `fluxo-alert-${uniqueId}` : `fluxo-alert-${Date.now()}`;
    const payload = JSON.stringify({
      title, body: message, url, icon: '/favicon.png', tag: notificationTag, renotify: true, priority: 'high'
    });

    const CHUNK_SIZE = 50; 
    for (let i = 0; i < rows.length; i += CHUNK_SIZE) {
      const chunk = rows.slice(i, i + CHUNK_SIZE);
      const promises = chunk.map(async (row) => {
        try {
          await webpush.sendNotification(row.subscription, payload);
        } catch (err: any) {
          if (err.statusCode === 410 || err.statusCode === 404) {
             try { await pool.query('DELETE FROM push_subscriptions WHERE subscription::text = $1', [JSON.stringify(row.subscription)]); } catch(e) {}
          }
        }
      });
      await Promise.all(promises);
    }
  } catch (error) {
    console.error("Falha no envio de Push:", error);
  }
};