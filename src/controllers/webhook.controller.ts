import { Request, Response } from 'express';
import { google } from 'googleapis';
import axios from 'axios'; 

// ==========================================
// ⚙️ CONFIGURAÇÕES DA AUTOMAÇÃO
// ==========================================
const SPREADSHEET_ID = 'COLA_AQUI_O_ID_DA_TUA_PLANILHA';
const FOLDER_ID = 'COLA_AQUI_O_ID_DA_PASTA_VIGIADA'; // Adicionado para sabermos onde procurar o ficheiro
const GREEN_API_URL = process.env.GREEN_API_URL || 'https://api.green-api.com/waInstanceXXXX/sendMessage/YYYY';

/**
 * ROTA PRINCIPAL: Lida com a receção dos webhooks do Google Drive
 */
export const handleDriveWebhook = async (req: Request, res: Response) => {
    try {
        const state = req.headers['x-goog-resource-state'] as string;
        const resourceId = req.headers['x-goog-resource-id'] as string;

        // 1. OBRIGATÓRIO: Responder imediatamente ao Google com status 200
        res.status(200).send('Webhook recebido');

        // 2. PROCESSAMENTO EM SEGUNDO PLANO
        if (state === 'sync') {
            console.log('✅ [Webhook] Canal do Drive sincronizado com sucesso!');
            return;
        }

        if (state === 'add' || state === 'update') {
            console.log(`📁 [Webhook] Alteração detetada no Drive! Recurso ID: ${resourceId}`);
            processNewDriveFile();
        }
    } catch (error) {
        console.error('❌ Erro no controlador do Webhook:', error);
    }
};

/**
 * FUNÇÃO DE AUTENTICAÇÃO: Lê o cofre do Render e cria o "Robô"
 */
const iniciarAutenticacaoGoogle = async () => {
    const credenciaisTexto = process.env.GOOGLE_CREDENTIALS;

    if (!credenciaisTexto) {
        throw new Error('A variável GOOGLE_CREDENTIALS não foi encontrada no ambiente (Render)!');
    }

    const credentials = JSON.parse(credenciaisTexto);

    const auth = new google.auth.GoogleAuth({
        credentials,
        scopes: [
            'https://www.googleapis.com/auth/drive.readonly', 
            'https://www.googleapis.com/auth/spreadsheets.readonly'
        ],
    });

    return await auth.getClient();
};

/**
 * FUNÇÃO SECUNDÁRIA: Lê a folha de cálculo do Google Sheets
 */
const obterListaTelefonicaDoSheets = async (authClient: any) => {
    const sheets = google.sheets({ version: 'v4', auth: authClient });
    const response = await sheets.spreadsheets.values.get({
        spreadsheetId: SPREADSHEET_ID,
        range: 'Página1!A:B', // Ajuste o nome da aba se necessário
    });

    const linhas = response.data.values;
    const listaTelefonica: Record<string, string> = {};

    if (linhas && linhas.length) {
        for (let i = 1; i < linhas.length; i++) {
            const email = linhas[i][0];
            const telefone = linhas[i][1];
            if (email && telefone) {
                listaTelefonica[email.toLowerCase().trim()] = telefone.trim();
            }
        }
    }
    return listaTelefonica;
};

/**
 * FUNÇÃO PRINCIPAL: Processa a alteração, busca o ficheiro e dispara o WhatsApp
 */
const processNewDriveFile = async () => {
    try {
        console.log('🔄 A iniciar a autenticação e lógica de notificação...');
        
        // 1. Inicia o nosso Robô
        const authClient = await iniciarAutenticacaoGoogle();
        const drive = google.drive({ version: 'v3', auth: authClient as any });

        // 2. Busca o ÚLTIMO ficheiro alterado dentro da pasta que estamos a vigiar
        const driveResponse = await drive.files.list({
            q: `'${FOLDER_ID}' in parents and trashed = false`,
            orderBy: 'modifiedTime desc', // Pega o mais recente
            pageSize: 1,
            fields: 'files(id, name, webViewLink, permissions)' // Pedimos também as permissões
        });

        const file = driveResponse.data.files?.[0];

        if (!file) {
            console.warn('⚠️ O webhook avisou de alteração, mas nenhum ficheiro foi encontrado na pasta.');
            return;
        }

        console.log(`📄 Ficheiro detetado: ${file.name}`);

        // 3. Extrai quem tem acesso a este ficheiro
        const emailsComAcesso = file.permissions
            ?.map(p => p.emailAddress?.toLowerCase())
            .filter(email => email !== undefined) as string[] || [];

        // 4. Vai buscar a nossa "Lista Telefónica" ao Google Sheets
        const listaTelefonica = await obterListaTelefonicaDoSheets(authClient);

        // 5. Cruzamento de Dados e Disparo (Green API)
        for (const email of emailsComAcesso) {
            const telefone = listaTelefonica[email];

            if (telefone) {
                const mensagem = `*Alerta Fluxo Royale* 🚀\n\nUm ficheiro que acompanhas foi atualizado:\n\n📁 *Ficheiro:* ${file.name}\n🔗 *Acesso:* ${file.webViewLink}`;
                
                console.log(`💬 Enviando WhatsApp para ${telefone} (Email: ${email})`);
                
                // DISPARO REAL (Remova os comentários quando quiser testar a Green API pra valer)
                /*
                try {
                    await axios.post(GREEN_API_URL, { 
                        chatId: `${telefone}@c.us`, 
                        message: mensagem 
                    });
                    console.log(`✅ Sucesso no envio para ${email}`);
                } catch (apiError) {
                    console.error(`❌ Falha na Green API para ${email}:`, apiError.message);
                }
                */
            } else {
                console.warn(`⚠️ O email ${email} tem acesso ao ficheiro, mas não tem o WhatsApp registado na lista.`);
            }
        }

    } catch (error) {
        console.error('❌ Erro durante o processamento da automação:', error);
    }
};
