import { Request, Response } from 'express';
import axios from 'axios';

// Memória temporária do servidor (Cache)
const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // 1. VERIFICA O CACHE DO SERVIDOR
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Servindo código ${code} direto do Cache ⚡`);
            return res.status(200).json(cached.data);
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // ==========================================
        // TENTATIVA 1: BrasilAPI
        // ==========================================
        try {
            console.log(`[Tracking] Tentativa 1: BrasilAPI para o código: ${code}`);
            const resBrasil = await axios.get(`https://brasilapi.com.br/api/correios/v1/${code}`, { 
                validateStatus: () => true,
                timeout: 8000 // Desiste se demorar mais de 8s
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
                        descricao: evt.descricao,
                        dtHrCriado: dataIso,
                        unidade: {
                            tipo: evt.local || "Unidade dos Correios",
                            endereco: { cidade: evt.cidade || "Desconhecido", uf: evt.uf || "" }
                        }
                    };
                });
                encontrouDados = true;
            }
        } catch (error: any) {
            console.log(`[Tracking] BrasilAPI falhou: ${error.message}`);
        }

        // ==========================================
        // TENTATIVA 2: Link&Track (Se a Tentativa 1 falhar)
        // ==========================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Tentativa 2: Link&Track para o código: ${code}`);
                const urlLink = `https://api.linketrack.com/track/json?user=teste&token=1abcd00b2731640e886fb41a8a9671ad1434c599dbaa0a0de9a5aa619f29a83f&codigo=${code}`;
                const resLink = await axios.get(urlLink, { 
                    validateStatus: () => true,
                    timeout: 8000 
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
                            descricao: evt.status, // Link&Track usa "status" em vez de "descricao"
                            dtHrCriado: dataIso,
                            unidade: {
                                tipo: "Local",
                                endereco: { cidade: evt.local || "Desconhecido", uf: "" }
                            }
                        };
                    });
                    encontrouDados = true;
                }
            } catch (error: any) {
                console.log(`[Tracking] Link&Track falhou: ${error.message}`);
            }
        }

        // ==========================================
        // FINALIZAÇÃO E RESPOSTA
        // ==========================================
        if (!encontrouDados || eventosFormatados.length === 0) {
            console.log(`[Tracking] Nenhuma API encontrou dados para ${code}.`);
            return res.status(200).json({ eventos: [] });
        }

        const resultFinal = { eventos: eventosFormatados };
        
        // Guarda na memória para a próxima pessoa que clicar nos próximos 15 minutos!
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        return res.status(200).json(resultFinal);

    } catch (error: any) {
        console.error('[Tracking] Erro crítico geral:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
