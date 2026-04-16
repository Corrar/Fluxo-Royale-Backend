import { Request, Response } from 'express';
import axios from 'axios';
import { rastrearEncomendas } from 'correios-brasil';

// Memória temporária do servidor (Cache) para não abusar das APIs
const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // 1. VERIFICA O CACHE DO SERVIDOR (Para velocidade máxima)
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Servindo código ${code} direto do Cache ⚡`);
            return res.status(200).json(cached.data);
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // =======================================================
        // TENTATIVA 1: Pacote Oficial 'correios-brasil' (O mais fiável)
        // =======================================================
        try {
            console.log(`[Tracking] Tentativa 1: correios-brasil para: ${code}`);
            const correiosRes = await rastrearEncomendas([code]);
            
            if (correiosRes && correiosRes[0] && correiosRes[0].eventos && correiosRes[0].eventos.length > 0) {
                eventosFormatados = correiosRes[0].eventos.map((evt: any) => ({
                    descricao: evt.descricao || evt.status || "Status atualizado",
                    dtHrCriado: evt.dtHrCriado || new Date().toISOString(),
                    unidade: {
                        tipo: evt.unidade?.tipo || "Local",
                        endereco: {
                            cidade: evt.unidade?.endereco?.cidade || evt.local || "Desconhecido",
                            uf: evt.unidade?.endereco?.uf || ""
                        }
                    },
                    unidadeDestino: evt.unidadeDestino ? {
                        tipo: evt.unidadeDestino.tipo || "Destino",
                        endereco: {
                            cidade: evt.unidadeDestino.endereco?.cidade || "",
                            uf: evt.unidadeDestino.endereco?.uf || ""
                        }
                    } : null
                }));
                encontrouDados = true;
                console.log(`[Tracking] Sucesso na Tentativa 1!`);
            }
        } catch (error: any) {
            console.log(`[Tracking] correios-brasil falhou: ${error.message}`);
        }

        // =======================================================
        // TENTATIVA 2: BrasilAPI (Excelente para códigos antigos)
        // =======================================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Tentativa 2: BrasilAPI para: ${code}`);
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
                            // BrasilAPI usa 'status' em vez de 'descricao' ou 'local'
                            descricao: evt.status || evt.descricao || "Status atualizado",
                            dtHrCriado: dataIso,
                            unidade: {
                                tipo: "Local",
                                endereco: { cidade: evt.local || evt.cidade || "Desconhecido", uf: evt.uf || "" }
                            }
                        };
                    });
                    encontrouDados = true;
                    console.log(`[Tracking] Sucesso na Tentativa 2!`);
                }
            } catch (error: any) {
                console.log(`[Tracking] BrasilAPI falhou: ${error.message}`);
            }
        }

        // =======================================================
        // TENTATIVA 3: Link&Track (Camuflado contra Cloudflare)
        // =======================================================
        if (!encontrouDados) {
            try {
                console.log(`[Tracking] Tentativa 3: Link&Track para: ${code}`);
                const urlLink = `https://api.linketrack.com/track/json?user=teste&token=1abcd00b2731640e886fb41a8a9671ad1434c599dbaa0a0de9a5aa619f29a83f&codigo=${code}`;
                const resLink = await axios.get(urlLink, { 
                    validateStatus: () => true,
                    timeout: 8000,
                    // Camuflagem para enganar o WAF (Fingir que somos um navegador Chrome)
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
                    console.log(`[Tracking] Sucesso na Tentativa 3!`);
                }
            } catch (error: any) {
                console.log(`[Tracking] Link&Track falhou: ${error.message}`);
            }
        }

        // =======================================================
        // FINALIZAÇÃO E RESPOSTA AO REACT
        // =======================================================
        if (!encontrouDados || eventosFormatados.length === 0) {
            console.log(`[Tracking] O Código ${code} realmente não possui dados em nenhuma das 3 APIs.`);
            return res.status(200).json({ eventos: [] });
        }

        const resultFinal = { eventos: eventosFormatados };
        
        // Guarda na memória apenas se houver sucesso
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        return res.status(200).json(resultFinal);

    } catch (error: any) {
        console.error('[Tracking] Erro crítico geral:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
