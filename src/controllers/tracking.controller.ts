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
            // Cria a tabela automaticamente se o utilizador ainda não a tiver criado!
            await client.query(`
                CREATE TABLE IF NOT EXISTS api_usage (
                    api_name VARCHAR(50) PRIMARY KEY,
                    request_count INT DEFAULT 0,
                    last_reset TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            `);
            await client.query(`
                INSERT INTO api_usage (api_name, request_count) 
                VALUES ('seu_rastreio', 0) ON CONFLICT DO NOTHING;
            `);

            // Lê o uso atual
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
            return res.status(200).json({ ...cached.data, usage: { count: usageCount, limit: 50 } });
        }

        // =======================================================
        // 3. BLOQUEIO DE SEGURANÇA SE ATINGIU 50
        // =======================================================
        if (usageCount >= 50) {
            console.log(`[Tracking] ⚠️ ALERTA: Limite de 50 rastreios mensais atingido! Bloqueando consulta para ${code}.`);
            return res.status(429).json({ error: 'LIMIT_REACHED' });
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // =======================================================
        // 4. TENTATIVA 1: SEU RASTREIO API
        // =======================================================
        try {
            console.log(`[Tracking] Consultando 'Seu Rastreio' para: ${code}`);
            
            // O Escudo Try/Catch aqui impede o Erro 500 se a rede falhar
            const url = `https://api.seurastreio.com.br/v1/trackings/${code}`;
            const resRastreio = await axios.get(url, {
                headers: { 'Authorization': `Bearer ${SEU_RASTREIO_TOKEN}` },
                validateStatus: () => true,
                timeout: 8000
            });

            // INCREMENTA O SEU USO NO BANCO
            if (resRastreio.status === 200 || resRastreio.status === 404) {
                const incClient = await pool.connect();
                try {
                    await incClient.query(`UPDATE api_usage SET request_count = request_count + 1 WHERE api_name = 'seu_rastreio'`);
                    usageCount += 1;
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
                    console.log(`[Tracking] Sucesso na API 'Seu Rastreio'!`);
                }
            }
        } catch (error: any) {
            console.log(`[Tracking] Seu Rastreio falhou (Caindo para o Plano B): ${error.message}`);
        }

        // =======================================================
        // 5. TENTATIVA 2: BRASILAPI (Plano B Gratuito e Ilimitado)
        // =======================================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Tentativa 2: BrasilAPI para: ${code}`);
                const resBrasil = await axios.get(`https://brasilapi.com.br/api/correios/v1/${code}`, { 
                    validateStatus: () => true, timeout: 8000
                });

                if (resBrasil.status === 200 && resBrasil.data?.eventos?.length > 0) {
                    eventosFormatados = resBrasil.data.eventos.map((evt: any) => {
                        let dataIso = new Date().toISOString();
                        try {
                            if (evt.data && evt.hora) {
                                const [dia, mes, ano] = evt.data.split('/');
                                dataIso = `${ano}-${mes}-${dia}T${evt.hora}:00`;
                            }
                        } catch (e) {}

                        return {
                            descricao: evt.descricao || evt.status || "Status atualizado",
                            dtHrCriado: dataIso,
                            unidade: {
                                tipo: "Local",
                                endereco: { cidade: evt.local || evt.cidade || "Desconhecido", uf: evt.uf || "" }
                            }
                        };
                    });
                    encontrouDados = true;
                    console.log(`[Tracking] Sucesso na BrasilAPI!`);
                }
            } catch (error: any) {
                console.log(`[Tracking] BrasilAPI falhou: ${error.message}`);
            }
        }

        // =======================================================
        // 6. RESPOSTA FINAL AO FRONTEND
        // =======================================================
        const resultFinal = { eventos: encontrouDados ? eventosFormatados : [] };
        
        // Guarda na memória
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        // Envia resposta incluindo a contagem de uso (ex: 1/50)
        return res.status(200).json({ ...resultFinal, usage: { count: usageCount, limit: 50 } });

    } catch (error: any) {
        console.error('[Tracking] Erro crítico geral:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
