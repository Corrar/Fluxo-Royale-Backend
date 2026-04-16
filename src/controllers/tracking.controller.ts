import { Request, Response } from 'express';
import axios from 'axios';
import { pool } from '../db';
import { rastrearEncomendas } from 'correios-brasil'; 

const SEU_RASTREIO_TOKEN = "sr_live_o8afqByB4GIqDCgQruI-kOzMuiKOLCRlYQf5r7QhmFE";

const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
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
        } catch (dbErr) {} finally { client.release(); }

        // =======================================================
        // 0. VERIFICAR O CACHE
        // =======================================================
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Código ${code} no Cache! ⚡`);
            return res.status(200).json({ ...cached.data, usage: { count: usageCount, limit: 50 } });
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // =======================================================
        // TENTATIVA 1: CORREIOS OFICIAL DIRETO (Traz Histórico Completo)
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
            console.log(`[Tracking] Tentativa 1 falhou: ${error.message}`);
        }

        // =======================================================
        // TENTATIVA 2: BRASILAPI (Traz Histórico Completo)
        // =======================================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Tentativa 2: BrasilAPI para: ${code}`);
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
            } catch (error: any) { console.log(`[Tracking] Tentativa 2 falhou: ${error.message}`); }
        }

        // =======================================================
        // TENTATIVA 3: SEU RASTREIO (Plano Free: Traz apenas o ÚLTIMO status)
        // =======================================================
        if (!encontrouDados && usageCount < 50) {
            try {
                console.log(`[Tracking] Tentativa 3: Seu Rastreio para ${code}`);
                const url = `https://api.seurastreio.com.br/v1/trackings/${code}`;
                
                const resRastreio = await axios.get(url, {
                    headers: { 'Authorization': `Bearer ${SEU_RASTREIO_TOKEN}` },
                    validateStatus: () => true, timeout: 8000
                });

                if (resRastreio.status === 200 || resRastreio.status === 404) {
                    const incClient = await pool.connect();
                    try {
                        await incClient.query(`UPDATE api_usage SET request_count = request_count + 1 WHERE api_name = 'seu_rastreio'`);
                        usageCount += 1;
                    } catch (e) {} finally { incClient.release(); }
                }

                if (resRastreio.status === 404) {
                    console.log(`[Tracking] Encomenda não encontrada. Registrando ${code} no painel Seu Rastreio...`);
                    try {
                        await axios.post('https://api.seurastreio.com.br/v1/trackings', { codigo: code }, {
                            headers: { 'Authorization': `Bearer ${SEU_RASTREIO_TOKEN}` },
                            validateStatus: () => true
                        });
                    } catch (postErr) {}
                }
                
                if (resRastreio.status === 200 && resRastreio.data) {
                    // Tenta achar o array historico. Se não achar (Plano Free), usa o objeto principal como um array de 1 item
                    let dadosBrutos = resRastreio.data.events || resRastreio.data.historico || resRastreio.data.eventos;
                    
                    if (!dadosBrutos || dadosBrutos.length === 0) {
                        // Plano gratuito detectado: pegamos os dados da raiz do JSON
                        if (resRastreio.data.status || resRastreio.data.description || resRastreio.data.descricao) {
                            dadosBrutos = [resRastreio.data];
                        } else {
                            dadosBrutos = [];
                        }
                    }

                    if (dadosBrutos.length > 0) {
                        eventosFormatados = dadosBrutos.map((evt: any) => ({
                            descricao: evt.status || evt.description || evt.descricao || "Status atualizado",
                            dtHrCriado: evt.date || evt.dataHora || evt.dtHrCriado || new Date().toISOString(),
                            unidade: { tipo: evt.location || "Local", endereco: { cidade: evt.city || evt.cidade || evt.local || "Desconhecido", uf: evt.state || evt.uf || "" } }
                        }));
                        encontrouDados = true;
                        console.log(`[Tracking] Sucesso na API 'Seu Rastreio' (Capturou ${dadosBrutos.length} evento(s)).`);
                    }
                }
            } catch (error: any) { console.log(`[Tracking] Tentativa 3 falhou: ${error.message}`); }
        }

        // =======================================================
        // TENTATIVA 4: Link&Track Camuflado (Último Recurso)
        // =======================================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Tentativa 4: Link&Track para: ${code}`);
                const urlLink = `https://api.linketrack.com/track/json?user=teste&token=1abcd00b2731640e886fb41a8a9671ad1434c599dbaa0a0de9a5aa619f29a83f&codigo=${code}`;
                const resLink = await axios.get(urlLink, { 
                    validateStatus: () => true, timeout: 8000,
                    headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36' }
                });

                if (resLink.status === 200 && resLink.data?.eventos?.length > 0) {
                    eventosFormatados = resLink.data.eventos.map((evt: any) => {
                        let dataIso = new Date().toISOString();
                        try {
                            if (evt.data && evt.hora) {
                                const [dia, mes, ano] = evt.data.split('/');
                                dataIso = `${ano}-${mes}-${dia}T${evt.hora}:00`;
                            }
                        } catch (e) {}
                        return {
                            descricao: evt.status,
                            dtHrCriado: dataIso,
                            unidade: { tipo: "Local", endereco: { cidade: evt.local || "Desconhecido", uf: "" } }
                        };
                    });
                    encontrouDados = true;
                }
            } catch (error: any) { console.log(`[Tracking] Tentativa 4 falhou: ${error.message}`); }
        }

        // =======================================================
        // RESPOSTA AO FRONTEND
        // =======================================================
        if (!encontrouDados || eventosFormatados.length === 0) {
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
