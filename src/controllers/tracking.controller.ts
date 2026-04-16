import { Request, Response } from 'express';
import axios from 'axios';

// Memória temporária (Cache) protege o limite gratuito da sua API!
const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos

// =========================================================
// ⚠️ INSIRA O SEU TOKEN DA API 'SEU RASTREIO' AQUI ⚠️
// =========================================================
const SEU_RASTREIO_TOKEN = "COLE_O_SEU_TOKEN_AQUI"; 

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // 1. VERIFICA O CACHE DO SERVIDOR (Não gasta cota da API)
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Servindo código ${code} direto do Cache ⚡`);
            return res.status(200).json(cached.data);
        }

        let eventosFormatados: any[] = [];
        let encontrouDados = false;

        // =======================================================
        // TENTATIVA 1: SEU RASTREIO API (A mais precisa)
        // =======================================================
        if (SEU_RASTREIO_TOKEN !== "sr_live_o8afqByB4GIqDCgQruI-kOzMuiKOLCRlYQf5r7QhmFE") {
            try {
                console.log(`[Tracking] Consultando 'Seu Rastreio' para: ${code}`);
                const url = `https://api.seurastreio.com.br/v1/trackings/${code}`; // URL Padrão da API deles
                
                const resRastreio = await axios.get(url, {
                    headers: { 'Authorization': `Bearer ${SEU_RASTREIO_TOKEN}` },
                    validateStatus: () => true, // Evita quebrar no 404
                    timeout: 8000
                });

                if (resRastreio.status === 200 && resRastreio.data) {
                    // A API deles costuma devolver os eventos numa destas chaves
                    const dadosBrutos = resRastreio.data.events || resRastreio.data.historico || resRastreio.data.eventos || [];

                    if (Array.isArray(dadosBrutos) && dadosBrutos.length > 0) {
                        eventosFormatados = dadosBrutos.map((evt: any) => {
                            return {
                                // Mapeia os dados independentemente de estarem em inglês ou pt-br
                                descricao: evt.status || evt.description || evt.descricao || "Status atualizado",
                                dtHrCriado: evt.date || evt.dataHora || evt.dtHrCriado || new Date().toISOString(),
                                unidade: {
                                    tipo: evt.location || "Local",
                                    endereco: { 
                                        cidade: evt.city || evt.cidade || evt.local || "Desconhecido", 
                                        uf: evt.state || evt.uf || "" 
                                    }
                                }
                            };
                        });
                        encontrouDados = true;
                        console.log(`[Tracking] Sucesso na API Seu Rastreio!`);
                    }
                } else if (resRastreio.status === 404) {
                    console.log(`[Tracking] Código ${code} não encontrado no Seu Rastreio.`);
                } else {
                    console.log(`[Tracking] Seu Rastreio retornou status ${resRastreio.status}. Limite atingido?`);
                }
            } catch (error: any) {
                console.log(`[Tracking] Seu Rastreio falhou: ${error.message}`);
            }
        }

        // =======================================================
        // TENTATIVA 2: BRASILAPI (Plano B Gratuito e Ilimitado)
        // =======================================================
        // Se a sua cota do 'Seu Rastreio' acabar, o sistema continua a funcionar usando a BrasilAPI
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
        // RESPOSTA FINAL AO FRONTEND
        // =======================================================
        if (!encontrouDados || eventosFormatados.length === 0) {
            console.log(`[Tracking] O Código ${code} não possui histórico em nenhuma API.`);
            // Devolve vazio para o React mostrar "Aguardando Atualização"
            return res.status(200).json({ eventos: [] });
        }

        const resultFinal = { eventos: eventosFormatados };
        
        // Guarda na memória apenas quando tem sucesso (Poupa a sua cota!)
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        return res.status(200).json(resultFinal);

    } catch (error: any) {
        console.error('[Tracking] Erro crítico geral:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
