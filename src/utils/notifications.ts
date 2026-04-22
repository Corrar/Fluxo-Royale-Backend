import webpush from 'web-push';
import { pool } from '../db';

export const sendPushNotificationToRole = async (
  role: string, 
  title: string, 
  message: string, 
  url: string = '/requests', 
  uniqueId?: string
) => {
  try {
    // ==========================================
    // 🚀 INTEGRAÇÃO COM WHATSAPP (VIA GREEN API)
    // ==========================================
    if (role === 'almoxarife') {
      
      // 1. Cole aqui as credenciais que você pegou no painel da Green API
      const idInstance = '7107596732'; 
      const apiTokenInstance = '4c4bebada0044e559765b9e11ddef3074b77721e5cb0428cb1';

      // ATENÇÃO À URL: A Green API às vezes usa subdomínios diferentes (ex: https://7103.api.greenapi.com)
      // Verifique no seu painel qual é a "API URL" correta da sua instância e troque abaixo se necessário.
      const greenApiUrl = `https://api.green-api.com/waInstance${idInstance}/sendMessage/${apiTokenInstance}`;

      // 2. Configure o número do Almoxarifado que vai RECEBER a mensagem
      // Formato OBRIGATÓRIO da Green API: DDI + DDD + NÚMERO + "@c.us"
      // Exemplo para o Brasil (55), DDD (11), número (999999999)
      const numeroAlmoxarifado = '5518997874513@c.us'; 

      // 3. Montamos o texto da mensagem (O asterisco * cria negrito no WhatsApp)
      const textoZap = `*🔔 NOVA SOLICITAÇÃO!*\n\n*${title}*\n${message}\n\nAcesse o sistema para verificar.`;

      // 4. Fazemos a requisição HTTP (fetch) para a API deles enviando os dados
      // Fazemos isso sem o comando "await", para que rode em segundo plano e não atrase o seu sistema!
      fetch(greenApiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json' // Avisamos que estamos enviando dados no formato JSON
        },
        body: JSON.stringify({
          chatId: numeroAlmoxarifado, // Para quem vai a mensagem
          message: textoZap           // Qual é o texto da mensagem
        })
      })
      .then(res => {
          if (res.ok) console.log(`✅ [WhatsApp] Alerta enviado ao Almoxarifado via Green API!`);
          else console.error(`❌ [WhatsApp] Erro na Green API. Status Code: ${res.status}`);
      })
      .catch(err => console.error(`❌ [WhatsApp] Falha de conexão com a Green API:`, err));
    }
    // ==========================================


    // ==========================================
    // 🌐 NOTIFICAÇÕES WEB PUSH (Originais do seu sistema)
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
