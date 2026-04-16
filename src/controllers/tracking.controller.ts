import { Request, Response } from 'express';
import axios from 'axios';

// Memória temporária do servidor (Cache)
const trackingCache = new Map<string, { data: any, timestamp: number }>();
const CACHE_TTL = 1000 * 60 * 15; // 15 minutos em milissegundos

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // 1. VERIFICA O CACHE PRIMEIRO
        const cached = trackingCache.get(code);
        if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
            console.log(`[Tracking] Servindo código ${code} direto do Cache ⚡`);
            return res.status(200).json(cached.data);
        }

        console.log(`[Tracking] Consultando BrasilAPI para o código: ${code} 🐢`);
        const url = `https://brasilapi.com.br/api/correios/v1/${code}`;
        const response = await axios.get(url, { validateStatus: () => true });

        // SE NÃO ENCONTRAR: Retorna vazio, mas NÃO GUARDA NO CACHE!
        // Assim, na próxima vez que o utilizador clicar, ele vai à API procurar de novo.
        if (response.status === 404) {
            console.log(`[Tracking] Código ${code} ainda sem histórico. Não será guardado no cache.`);
            return res.status(200).json({ eventos: [] });
        }

        if (response.status !== 200) throw new Error(`Status ${response.status}`);

        const data = response.data;
        if (!data || !data.eventos || data.eventos.length === 0) {
             return res.status(200).json({ eventos: [] });
        }

        const eventosFormatados = data.eventos.map((evt: any) => {
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

        const resultFinal = { eventos: eventosFormatados };

        // 2. COMO ENCONTROU DADOS REAIS, AGORA SIM GUARDA NO CACHE
        trackingCache.set(code, { data: resultFinal, timestamp: Date.now() });

        return res.status(200).json(resultFinal);

    } catch (error: any) {
        console.error('[Tracking] Erro crítico ao buscar rastreio:', error.message);
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio.' });
    }
};
