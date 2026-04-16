import { Request, Response } from 'express';
import axios from 'axios';
import { pool } from '../db';

// A sua Chave Oficial
const SEU_RASTREIO_TOKEN = "sr_live_o8afqByB4GIqDCgQruI-kOzMuiKOLCRlYQf5r7QhmFE";

// Cache para não gastar o limite se alguém atualizar a página (15 min)
const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; 

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // =======================================================
        // 1. GESTÃO DO LIMITE NO BANCO DE DADOS (50/mês)
        // =======================================================
        const client = await pool.connect();
        let usageCount = 0;
        try {
            const resUsage = await client.query(`
                SELECT request_count, 
                       EXTRACT(MONTH FROM last_reset) as reset_month, 
                       EXTRACT(MONTH FROM CURRENT_TIMESTAMP) as curr_month 
                FROM api_usage WHERE api_name = 'seu_rastreio'
            `);
            
            if (resUsage.rows.length > 0) {
                const usage = resUsage.rows[0];
                // Se virou o mês, reseta o contador para Zero!
                if (usage.reset_month !== usage.curr_month) {
                    await client.query(`UPDATE api_usage SET request_count = 0, last_reset = CURRENT_TIMESTAMP WHERE api_name = 'seu_rastreio'`);
                    usageCount = 0;
                } else {
                    usageCount = usage.request_count;
                }
            }
        } catch (dbErr) {
            console.error('[Tracking] Erro na verificação do banco de dados:', dbErr);
        } finally {
            client.release();
        }

        // =======================================================
        // 2. VERIFICAR O CACHE (As consultas aqui não gastam o seu limite!)
        // =======================================================
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Código ${code} no Cache! Cota poupada. ⚡`);
            // Envia os dados com a contagem acoplada
            return res.status(200).json({ ...cached.data, usage: { count: usageCount, limit: 50 } });
        }

        // =======================================================
        // 3. BLOQUEIO DE SEGURANÇA SE ATINGIU 50
        // =======================================================
        if (usageCount >= 50) {
            console.log(`[Tracking] ⚠️ ALERTA: Limite de 50 rastreios mensais atingido! Bloqueando consulta para ${code}.`);
            return res.status(429).json({ error: 'LIMIT_REACHED' });
        }

        // =======================================================
        // 4. FAZER A CONSULTA NA API
        // =======================================================
        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        console.log(`[Tracking] Consultando 'Seu Rastreio' para: ${code}`);
        const url = `https://api.seurastreio.com.br/v1/trackings/${code}`;
        const resRastreio = await axios.get(url, {
            headers: { 'Authorization': `Bearer ${SEU_RASTREIO_TOKEN}` },
            validateStatus: () => true,
            timeout: 8000
        });

        // INCREMENTA O SEU USO NO BANCO (porque fez uma requisição à API)
        if (resRastreio.status === 200 || resRastreio.status === 404) {
            const incClient = await pool.connect();
            try {
                await incClient.query(`UPDATE api_usage SET request_count = request_count + 1 WHERE api_name = 'seu_rastreio'`);
                usageCount += 1; // Atualiza a variável para mandar ao frontend
            } catch (e) {} finally { incClient.release(); }
        }

        if (resRastreio.status === 200 && resRastreio.data) {
            const dadosBrutos = resRastreio.data.events || resRastreio.data.historico || resRastreio.data.eventos || [];
            if (Array.isArray(dadosBrutos) && dadosBrutos.length > 0) {
                eventosFormatados = dadosBrutos.map((evt: any) => ({
                    descricao: evt.status || evt.description || evt.descricao || "Status atualizado",
                    dtHrCriado: evt.date || evt.dataHora || evt.dtHrCriado || new Date().toISOString(),
                    unidade: {
                        tipo: evt.location || "Local",
                        endereco: { cidade: evt.city || evt.cidade || evt.local || "Desconhecido", uf: evt.state || evt.uf || "" }
                    }
                }));
                encontrouDados = true;
            }
        }

        // =======================================================
        // 5. RESPOSTA FINAL AO FRONTEND
        // =======================================================
        const resultFinal = { eventos: encontrouDados ? eventosFormatados : [] };
        
        // Guarda na memória
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        // Envia resposta incluindo a contagem de uso!
        return res.status(200).json({ ...resultFinal, usage: { count: usageCount, limit: 50 } });

    } catch (error: any) {
        console.error('[Tracking] Erro crítico geral:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
