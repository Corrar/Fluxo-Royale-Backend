import webpush from 'web-push';
import { pool } from '../db';
// 1. Importamos a função do WhatsApp que criamos no arquivo whatsapp.ts
import { sendWhatsAppMessage } from './whatsapp';

export const sendPushNotificationToRole = async (
  role: string, 
  title: string, 
  message: string, 
  url: string = '/requests', 
  uniqueId?: string
) => {
  try {
    // ==========================================
    // 🚀 INTEGRAÇÃO COM WHATSAPP
    // ==========================================
    // Se a notificação for para o almoxarifado, enviamos mensagem via WhatsApp
    if (role === 'almoxarife') {
      // ATENÇÃO: Substitua este número pelo número real do WhatsApp do almoxarifado!
      // Formato exigido: DDI (55) + DDD (ex: 11) + Número. Tudo junto, sem espaços ou traços.
      const numeroAlmoxarifado = '5518997874513'; 
      
      // Montamos o texto da mensagem. O asterisco (*) deixa o texto em negrito no WhatsApp.
      const textoZap = `*🔔 NOVA SOLICITAÇÃO!*\n\n*${title}*\n${message}\n\nAcesse o sistema para verificar.`;
      
      // Disparamos a mensagem. 
      // Nota didática: Não usamos "await" propositalmente para que o código continue rodando 
      // imediatamente, sem atrasar a vida do usuário que fez a solicitação no sistema.
      sendWhatsAppMessage(numeroAlmoxarifado, textoZap);
    }
    // ==========================================


    // ==========================================
    // 🌐 NOTIFICAÇÕES WEB PUSH (Originais)
    // ==========================================
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
