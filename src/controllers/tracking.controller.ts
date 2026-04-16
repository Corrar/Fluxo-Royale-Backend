import { Request, Response } from 'express';
import axios from 'axios';
import { pool } from '../db';

// Chave fornecida pelo usuário
const WONCA_API_KEY = "bNamHEjNg2ibpZgOkZDNHuGbuoVhvMap-X_MZKDK20U";
const API_LIMIT = 1000;

const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // =======================================================
        // 1. GESTÃO DE LIMITES DA API (1000 requisições por mês)
        // =======================================================
        let usageCount = 0;
        const client = await pool.connect();
        try {
            const resUsage = await client.query(`
                SELECT request_count, EXTRACT(MONTH FROM last_reset) as reset_month, EXTRACT(MONTH FROM CURRENT_TIMESTAMP) as curr_month 
                FROM api_usage WHERE api_name = 'seu_rastreio'
            `);
            if (resUsage.rows.length > 0) {
                const usage = resUsage.rows[0];
                if (usage.reset_month !== usage.curr_month) {
                    await client.query(`UPDATE api_usage SET request_count = 0, last_reset = CURRENT_TIMESTAMP WHERE api_name = 'seu_rastreio'`);
                    usageCount = 0;
                } else {
                    usageCount = usage.request_count;
                }
            } else {
                await client.query(`INSERT INTO api_usage (api_name, request_count, last_reset) VALUES ('seu_rastreio', 0, CURRENT_TIMESTAMP)`);
            }
        } catch (dbErr) {
            console.log('[Tracking] Erro ao ler limite DB:', dbErr);
        } finally { 
            client.release(); 
        }

        // =======================================================
        // 2. VERIFICAÇÃO DO CACHE DA MEMÓRIA
        // =======================================================
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Código ${code} no Cache! ⚡`);
            return res.status(200).json({ ...cached.data, usage: { count: usageCount, limit: API_LIMIT } });
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // =======================================================
        // TENTATIVA 1: WONCA LABS (API Oficial - Método POST)
        // =======================================================
        if (usageCount < API_LIMIT) {
            try {
                console.log(`[Tracking] Consultando Wonca Labs (POST) para: ${code}`);
                
                const url = `https://api-labs.wonca.com.br/wonca.labs.v1.LabsService/Track`;
                
                const resWonca = await axios.post(url, 
                    { code: code }, // Corpo da requisição conforme a documentação
                    {
                        headers: { 
                            'Content-Type': 'application/json',
                            'Authorization': `Apikey ${WONCA_API_KEY}` // Formato Apikey conforme doc
                        },
                        timeout: 10000
                    }
                );

                // Se a API respondeu, incrementa o uso
                if (resWonca.status === 200) {
                    const incClient = await pool.connect();
                    try {
                        await incClient.query(`UPDATE api_usage SET request_count = request_count + 1 WHERE api_name = 'seu_rastreio'`);
                        usageCount += 1;
                    } catch (e) {} finally { incClient.release(); }

                    // A Wonca Labs geralmente retorna um objeto com os eventos diretamente ou dentro de um campo 'events'
                    // Vamos adaptar para o formato que o seu Frontend já espera.
                    const data = resWonca.data;
                    
                    // Nota: Se a estrutura de resposta da Wonca Labs mudar, ajustamos aqui.
                    // Baseado no histórico dessas APIs, o campo costuma ser 'eventos' ou 'events'
                    const rawEvents = data.eventos || data.events || data.historico || [];

                    if (Array.isArray(rawEvents) && rawEvents.length > 0) {
                        eventosFormatados = rawEvents.map((evt: any) => {
                            let cidadeStr = evt.local || evt.location || "Desconhecido";
                            let ufStr = "";
                            if (cidadeStr.includes('/')) {
                                const parts = cidadeStr.split('/');
                                cidadeStr = parts[0].trim();
                                ufStr = parts[1].trim();
                            }

                            return {
                                descricao: evt.descricao || evt.status || "Status atualizado",
                                dtHrCriado: evt.data || evt.date || evt.dataHora || new Date().toISOString(),
                                unidade: { 
                                    tipo: "Local", 
                                    endereco: { cidade: cidadeStr, uf: ufStr } 
                                },
                                unidadeDestino: evt.destino ? { 
                                    tipo: "Destino", 
                                    endereco: { cidade: evt.destino, uf: "" } 
                                } : null
                            };
                        });
                        encontrouDados = true;
                        console.log(`[Tracking] Sucesso na Wonca Labs para o código: ${code}`);
                    }
                }
            } catch (error: any) { 
                console.log(`[Tracking] Falha na Wonca Labs: ${error.message}`); 
                // Se der erro 403/401, o token ou a URL podem estar errados
                if (error.response) console.log('[Tracking] Erro Detalhado:', error.response.data);
            }
        }

        // =======================================================
        // TENTATIVA 2: FALLBACK (Brasil API)
        // =======================================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Recorrendo ao Fallback BrasilAPI para: ${code}`);
                const resBrasil = await axios.get(`https://brasilapi.com.br/api/correios/v1/${code}`, { validateStatus: () => true, timeout: 8000 });

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
                            descricao: evt.descricao || "Status atualizado",
                            dtHrCriado: dataIso,
                            unidade: { tipo: "Local", endereco: { cidade: evt.local || evt.cidade || "Desconhecido", uf: evt.uf || "" } },
                            unidadeDestino: null
                        };
                    });
                    encontrouDados = true;
                }
            } catch (error: any) {}
        }

        // =======================================================
        // RESPOSTA FINAL
        // =======================================================
        if (!encontrouDados || eventosFormatados.length === 0) {
            return res.status(200).json({ eventos: [], usage: { count: usageCount, limit: API_LIMIT } });
        }

        const resultFinal = { eventos: eventosFormatados };
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        return res.status(200).json({ ...resultFinal, usage: { count: usageCount, limit: API_LIMIT } });

    } catch (error: any) {
        console.error('[Tracking] Erro crítico geral:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
