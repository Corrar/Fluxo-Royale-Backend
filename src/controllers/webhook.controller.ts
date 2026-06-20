import { Request, Response } from 'express';
import { google } from 'googleapis';
import axios from 'axios'; // Biblioteca para fazer a requisição HTTP para a Green API
import * as logger from '../utils/logger';

// Quando fores para produção, colocarás o ID real da planilha aqui
const SPREADSHEET_ID = 'COLA_AQUI_O_ID_DA_TUA_PLANILHA';

// Dados da tua Green API (serão colocados no teu ficheiro .env no futuro)
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
            logger.info('✅ [Webhook] Canal do Drive sincronizado com sucesso!');
            return;
        }

        if (state === 'add' || state === 'update') {
            logger.info(`📁 [Webhook] Alteração detetada no Drive! Recurso ID: ${resourceId}`);
            // Não usamos o "await" aqui para não prender a resposta ao Google
            processNewDriveFile(resourceId);
        }
    } catch (error) {
        logger.error('❌ Erro no controlador do Webhook:', error);
    }
};

/**
 * FUNÇÃO DE PRODUÇÃO: Lê a folha de cálculo (Está pronta, mas não a vamos usar já)
 */
const obterListaTelefonicaDoSheets = async (authClient: any) => {
    const sheets = google.sheets({ version: 'v4', auth: authClient });
    const response = await sheets.spreadsheets.values.get({
        spreadsheetId: SPREADSHEET_ID,
        range: 'Página1!A:B', 
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
 * FUNÇÃO PRINCIPAL: Processa o ficheiro, cruza os dados e envia a mensagem
 */
const processNewDriveFile = async (resourceId: string) => {
    try {
        logger.info('A iniciar lógica de notificação...');

        // ---------------------------------------------------------
        // MODO TESTE (MOCKS): Imitando a resposta do Google Drive
        // ---------------------------------------------------------
        const fileMock = {
            name: 'Projeto_Nova_Maquina.pdf',
            link: 'https://drive.google.com/file/d/123/view',
            permissions: [
                { emailAddress: 'engenharia@fluxo-royale.com.br' },
                { emailAddress: 'producao@fluxo-royale.com.br' }
            ]
        };

        const emailsComAcesso = fileMock.permissions
            .map(p => p.emailAddress?.toLowerCase())
            .filter(email => email !== undefined) as string[];

        // ---------------------------------------------------------
        // MODO TESTE (MOCKS): Imitando a folha de cálculo (Google Sheets)
        // ---------------------------------------------------------
        const listaTelefonicaMock: Record<string, string> = {
            'producao@fluxo-royale.com.br': '5511999999999', // O número fingido da produção
            // Repara que não colocámos a engenharia aqui propositadamente para testar o aviso de erro
        };

        // ---------------------------------------------------------
        // CRUZAMENTO DE DADOS E DISPARO (GREEN API)
        // ---------------------------------------------------------
        for (const email of emailsComAcesso) {
            // No futuro, trocaremos "listaTelefonicaMock" pela função real
            const telefone = listaTelefonicaMock[email];

            if (telefone) {
                const mensagem = `*Alerta Fluxo Royale* 🚀\n\nUm ficheiro que acompanhas foi atualizado:\n\n📁 *Ficheiro:* ${fileMock.name}\n🔗 *Acesso:* ${fileMock.link}`;
                
                // MODO TESTE: Apenas registamos no terminal em vez de enviar o WhatsApp real
                logger.info(`💬 [SIMULAÇÃO GREEN API] Enviando para ${telefone} (Email: ${email}):\n${mensagem}`);
                
                // CÓDIGO DE PRODUÇÃO (Descomentar futuramente):
                // await axios.post(GREEN_API_URL, { 
                //     chatId: `${telefone}@c.us`, 
                //     message: mensagem 
                // });
            } else {
                logger.warn(`⚠️ O email ${email} tem acesso ao ficheiro, mas não tem o WhatsApp registado na lista.`);
            }
        }

    } catch (error) {
        logger.error('❌ Erro durante o processamento do ficheiro:', error);
    }
};
