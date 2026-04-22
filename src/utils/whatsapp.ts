// Arquivo: src/utils/whatsapp.ts
import { Client, LocalAuth } from 'whatsapp-web.js';
import qrcode from 'qrcode-terminal';

// Configuração do Cliente WhatsApp
// O LocalAuth é o segredo para a estabilidade: ele salva a sessão na pasta .wwebjs_auth/
const client = new Client({
    authStrategy: new LocalAuth(),
    puppeteer: {
        // Esses argumentos são cruciais para evitar travamentos em servidores (como Linux ou VPS)
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
    }
});

let isReady = false;

// Evento: Quando o sistema precisar que você escaneie o QR Code
client.on('qr', (qr) => {
    console.log('📱 [WhatsApp] Escaneie o QR Code abaixo com o WhatsApp que fará os envios:');
    qrcode.generate(qr, { small: true });
});

// Evento: Quando a conexão for estabelecida com sucesso
client.on('ready', () => {
    console.log('✅ [WhatsApp] Conectado e pronto para enviar mensagens!');
    isReady = true;
});

// Evento: Se a conexão cair (celular sem bateria muito tempo, etc)
client.on('disconnected', (reason) => {
    console.log('❌ [WhatsApp] Desconectado. Motivo:', reason);
    isReady = false;
    // Tenta reiniciar o cliente automaticamente
    client.initialize().catch(console.error);
});

// Função para iniciar o robô (chamaremos isso no server.ts)
export const initWhatsApp = () => {
    console.log('⏳ [WhatsApp] Iniciando cliente...');
    client.initialize().catch(console.error);
};

// Função para enviar a mensagem
export const sendWhatsAppMessage = async (toPhone: string, message: string) => {
    if (!isReady) {
        console.error('⚠️ [WhatsApp] Sistema não está pronto. Mensagem ignorada.');
        return;
    }

    try {
        // O formato do número no WhatsApp Web exige que termine com @c.us
        // Exemplo: 5511999999999@c.us
        const chatId = toPhone.includes('@') ? toPhone : `${toPhone}@c.us`;
        await client.sendMessage(chatId, message);
        console.log(`✅ [WhatsApp] Mensagem enviada com sucesso para ${toPhone}`);
    } catch (error) {
        console.error('❌ [WhatsApp] Erro ao enviar mensagem:', error);
    }
};
