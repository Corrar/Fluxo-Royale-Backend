import { Request, Response } from 'express';
import axios from 'axios';
import { pool } from '../db';
import { rastrearEncomendas } from 'correios-brasil'; 

// Chave da API Oficial
const SEU_RASTREIO_TOKEN = "sr_live_o8afqByB4GIqDCgQruI-kOzMuiKOLCRlYQf5r7QhmFE";
// Substitua a palavra "teste" abaixo se você criou uma URL personalizada no painel deles!
const SEU_RASTREIO_BASE_URL = "https://teste.seurastreio.com.br/api/public/rastreio";

const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos de cache

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // =======================================================
        // 1. GESTÃO DO LIMITE MENSAL NO BANCO DE DADOS (50 Rastreios/Mês)
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
            }
        } catch (dbErr) {
            console.log('[Tracking] Erro DB Limite:', dbErr);
        } finally { 
            client.release(); 
        }

        // =======================================================
        // 2. VERIFICAR O CACHE DA MEMÓRIA
        // =======================================================
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Código ${code} lido do Cache! ⚡`);
            return res.status(200).json({ ...cached.data, usage: { count: usageCount, limit: 50 } });
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // =======================================================
        // TENTATIVA 1: CORREIOS OFICIAL (Sem limites, histórico completo)
        // =======================================================
        try {
            console.log(`[Tracking] Tentativa 1: correios-brasil para ${code}`);
            const correiosRes = await rastrearEncomendas([code]);
            
            if (correiosRes && correiosRes[0] && correiosRes[0].eventos && correiosRes[0].eventos.length > 0) {
                eventosFormatados = correiosRes[0].eventos.map((evt: any) => ({
                    descricao: evt.descricao || evt.status || "Status atualizado",
                    dtHrCriado: evt.dtHrCriado || new Date().toISOString(),
                    unidade: {
                        tipo: evt.unidade?.tipo || "Local",
                        endereco: { cidade: evt.unidade?.endereco?.cidade || evt.local || "Desconhecido", uf: evt.unidade?.endereco?.uf || "" }
                    },
                    unidadeDestino: evt.unidadeDestino ? {
                        tipo: evt.unidadeDestino.tipo || "Destino",
                        endereco: { cidade: evt.unidadeDestino.endereco?.cidade || "", uf: evt.unidadeDestino.endereco?.uf || "" }
                    } : null
                }));
                encontrouDados = true;
            }
        } catch (error: any) {
            console.log(`[Tracking] Tentativa 1 falhou.`);
        }

        // =======================================================
        // TENTATIVA 2: SEU RASTREIO API (Exatamente como manda a Documentação)
        // =======================================================
        if (!encontrouDados && usageCount < 50) {
            try {
                console.log(`[Tracking] Tentativa 2: Seu Rastreio para ${code}`);
                
                const url = `${SEU_RASTREIO_BASE_URL}/${code}`;
                const resRastreio = await axios.get(url, {
                    headers: { 'Authorization': `Bearer ${SEU_RASTREIO_TOKEN}` },
                    validateStatus: () => true, 
                    timeout: 8000
                });

                // Valida o incremento na DB de limites
                if (resRastreio.status === 200) {
                    const incClient = await pool.connect();
                    try {
                        await incClient.query(`UPDATE api_usage SET request_count = request_count + 1 WHERE api_name = 'seu_rastreio'`);
                        usageCount += 1;
                    } catch (e) {} finally { incClient.release(); }
                }

                // Parse dos dados conforme a documentação
                if (resRastreio.status === 200 && resRastreio.data?.success) {
                    const data = resRastreio.data;
                    
                    // Se for conta paga, usa o 'historico'. Se for grátis, usa o 'eventoMaisRecente' e converte num Array.
                    let baseEventos = [];
                    if (data.historico && data.historico.length > 0) {
                        baseEventos = data.historico;
                    } else if (data.eventoMaisRecente) {
                        baseEventos = [data.eventoMaisRecente];
                    }

                    if (baseEventos.length > 0) {
                        eventosFormatados = baseEventos.map((evt: any) => ({
                            descricao: evt.descricao || "Status atualizado",
                            dtHrCriado: evt.data || new Date().toISOString(),
                            unidade: { 
                                tipo: "Local", 
                                endereco: { cidade: evt.local || "Desconhecido", uf: "" } 
                            },
                            unidadeDestino: evt.destino ? { tipo: "Destino", endereco: { cidade: evt.destino, uf: "" } } : null
                        }));
                        encontrouDados = true;
                        console.log(`[Tracking] Sucesso na API 'Seu Rastreio'!`);
                    }
                } else if (resRastreio.status === 401) {
                    console.log(`[Tracking] Erro de Autenticação Seu Rastreio: Chave inválida.`);
                } else if (resRastreio.status === 429) {
                    console.log(`[Tracking] Limite de chamadas do Seu Rastreio excedido (Rate Limit).`);
                }
            } catch (error: any) { 
                console.log(`[Tracking] Tentativa 2 falhou: ${error.message}`); 
            }
        }

        // =======================================================
        // TENTATIVA 3: BRASILAPI (Plano de Emergência)
        // =======================================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Tentativa 3: BrasilAPI para: ${code}`);
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
                            descricao: evt.descricao || evt.status || "Status atualizado",
                            dtHrCriado: dataIso,
                            unidade: { tipo: "Local", endereco: { cidade: evt.local || evt.cidade || "Desconhecido", uf: evt.uf || "" } }
                        };
                    });
                    encontrouDados = true;
                }
            } catch (error: any) { console.log(`[Tracking] Tentativa 3 falhou: ${error.message}`); }
        }

        // =======================================================
        // RESPOSTA AO FRONTEND
        // =======================================================
        if (!encontrouDados || eventosFormatados.length === 0) {
            // Devolve sempre vazio no caso de não encontrar, para a tela de 'Aguardando Atualização' aparecer.
            return res.status(200).json({ eventos: [], usage: { count: usageCount, limit: 50 } });
        }

        const resultFinal = { eventos: eventosFormatados };
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        return res.status(200).json({ ...resultFinal, usage: { count: usageCount, limit: 50 } });

    } catch (error: any) {
        console.error('[Tracking] Erro crítico geral:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
