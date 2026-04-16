import { Request, Response } from 'express';
import axios from 'axios';
import { pool } from '../db';

// A sua chave de API gerada no Dashboard do Seu Rastreio
const SEU_RASTREIO_TOKEN = "sr_live_o8afqByB4GIqDCgQruI-kOzMuiKOLCRlYQf5r7QhmFE";

const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // 1. GESTÃO DE LIMITES DA API (50 requisições por mês)
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
            console.log('[Tracking] Erro ao ler limite DB:', dbErr);
        } finally { 
            client.release(); 
        }

        // 2. VERIFICAÇÃO DO CACHE DA MEMÓRIA
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Código ${code} no Cache! ⚡`);
            return res.status(200).json({ ...cached.data, usage: { count: usageCount, limit: 50 } });
        }

        // =======================================================
        // MODO DE TESTE PARA O FRONTEND (Pode apagar no futuro)
        // =======================================================
        if (code === 'TESTE123BR') {
            console.log('[Tracking] MODO DE TESTE ATIVADO! Gerando pacote falso.');
            return res.status(200).json({
                usage: { count: usageCount, limit: 50 },
                eventos: [
                    {
                        descricao: "Objeto entregue ao destinatário",
                        dtHrCriado: new Date().toISOString(),
                        unidade: { tipo: "Unidade de Distribuição", endereco: { cidade: "Adamantina", uf: "SP" } }
                    },
                    {
                        descricao: "Objeto saiu para entrega ao destinatário",
                        dtHrCriado: new Date(Date.now() - 4000000).toISOString(),
                        unidade: { tipo: "Unidade de Distribuição", endereco: { cidade: "Adamantina", uf: "SP" } }
                    },
                    {
                        descricao: "Objeto em trânsito - por favor aguarde",
                        dtHrCriado: new Date(Date.now() - 86400000).toISOString(),
                        unidade: { tipo: "Unidade de Tratamento", endereco: { cidade: "Bauru", uf: "SP" } },
                        unidadeDestino: { tipo: "Unidade de Distribuição", endereco: { cidade: "Adamantina", uf: "SP" } }
                    },
                    {
                        descricao: "Objeto postado",
                        dtHrCriado: new Date(Date.now() - 172800000).toISOString(),
                        unidade: { tipo: "Agência dos Correios", endereco: { cidade: "São Paulo", uf: "SP" } }
                    }
                ]
            });
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // =======================================================
        // INTEGRAÇÃO OFICIAL: SEU RASTREIO API
        // =======================================================
        if (usageCount < 50) {
            try {
                console.log(`[Tracking] Consultando Seu Rastreio para: ${code}`);
                
                // URL Base oficial. (Se a sua loja tiver um slug configurado, troque o "api" pelo seu slug)
                const url = `https://api.seurastreio.com.br/api/public/rastreio/${code}`;
                
                const resRastreio = await axios.get(url, {
                    headers: { 'Authorization': `Bearer ${SEU_RASTREIO_TOKEN}` },
                    validateStatus: () => true, // Não quebra no 404
                    timeout: 8000
                });

                // Atualiza contagem de uso no banco
                if (resRastreio.status === 200 || resRastreio.status === 404) {
                    const incClient = await pool.connect();
                    try {
                        await incClient.query(`UPDATE api_usage SET request_count = request_count + 1 WHERE api_name = 'seu_rastreio'`);
                        usageCount += 1;
                    } catch (e) {} finally { incClient.release(); }
                }

                // Processamento exato da documentação (Sucesso = 200 e success = true)
                if (resRastreio.status === 200 && resRastreio.data?.success) {
                    const data = resRastreio.data;
                    
                    let baseEventos: any[] = [];
                    
                    // Se tiver o plano pago, pega o 'historico'. Se for grátis, pega o 'eventoMaisRecente'
                    if (data.historico && Array.isArray(data.historico)) {
                        baseEventos = data.historico;
                    } else if (data.eventoMaisRecente) {
                        baseEventos = [data.eventoMaisRecente];
                    }

                    if (baseEventos.length > 0) {
                        eventosFormatados = baseEventos.map((evt: any) => {
                            // Extrai a cidade e a UF se vier no formato "São Paulo/SP"
                            let cidadeStr = evt.local || "Desconhecido";
                            let ufStr = "";
                            if (cidadeStr.includes('/')) {
                                const parts = cidadeStr.split('/');
                                cidadeStr = parts[0].trim();
                                ufStr = parts[1].trim();
                            }

                            return {
                                descricao: evt.descricao || "Status atualizado",
                                dtHrCriado: evt.data || new Date().toISOString(),
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
                        console.log(`[Tracking] API Seu Rastreio encontrou a encomenda!`);
                    }
                } else {
                    console.log(`[Tracking] Seu Rastreio não encontrou (Status: ${resRastreio.status})`);
                }
            } catch (error: any) { 
                console.log(`[Tracking] Falha na comunicação com Seu Rastreio: ${error.message}`); 
            }
        }

        // =======================================================
        // FALLBACK: BRASIL API (O plano de emergência ilimitado)
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
                    console.log(`[Tracking] Fallback BrasilAPI funcionou!`);
                }
            } catch (error: any) { console.log(`[Tracking] BrasilAPI falhou: ${error.message}`); }
        }

        // =======================================================
        // RESPOSTA AO FRONTEND
        // =======================================================
        if (!encontrouDados || eventosFormatados.length === 0) {
            // Se o código for muito velho ou ainda não foi postado, ele cai aqui.
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
