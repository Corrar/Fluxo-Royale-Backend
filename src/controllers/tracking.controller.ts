import { Request, Response } from 'express';
import axios from 'axios';

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        console.log(`[Tracking] Consultando BrasilAPI para o código: ${code}`);
        
        // Utilizamos a BrasilAPI: estável, gratuita e sem tokens
        const url = `https://brasilapi.com.br/api/correios/v1/${code}`;
        
        // validateStatus garante que o axios não "quebre" se a API devolver erro 404 (Objeto não encontrado)
        const response = await axios.get(url, { validateStatus: () => true });

        // Se o objeto ainda não foi postado ou não existe, a BrasilAPI devolve 404
        if (response.status === 404) {
            console.log(`[Tracking] Código ${code} ainda não encontrado na base dos Correios.`);
            return res.status(200).json({ eventos: [] });
        }

        if (response.status !== 200) {
            throw new Error(`A BrasilAPI retornou status ${response.status}`);
        }

        const data = response.data;

        if (!data || !data.eventos || data.eventos.length === 0) {
             return res.status(200).json({ eventos: [] });
        }

        // Formatamos os dados da BrasilAPI para o Frontend (React) não precisar mudar nada
        const eventosFormatados = data.eventos.map((evt: any) => {
            let dataIso = new Date().toISOString(); // Fallback seguro
            
            try {
                // A BrasilAPI devolve data: "DD/MM/YYYY" e hora: "HH:MM"
                if (evt.data && evt.hora) {
                    const [dia, mes, ano] = evt.data.split('/');
                    dataIso = `${ano}-${mes}-${dia}T${evt.hora}:00`;
                }
            } catch (e) {
                console.log("[Tracking] Erro ao formatar a data:", e);
            }

            return {
                descricao: evt.descricao,
                dtHrCriado: dataIso,
                unidade: {
                    tipo: evt.local || "Unidade dos Correios",
                    endereco: {
                        cidade: evt.cidade || "Desconhecido",
                        uf: evt.uf || ""
                    }
                }
            };
        });

        // Devolve o array pronto para a Timeline do Frontend
        return res.status(200).json({ eventos: eventosFormatados });

    } catch (error: any) {
        console.error('[Tracking] Erro crítico ao buscar rastreio:', error.message);
        // Mantemos o erro 500 em caso de falha crítica na nossa API ou na rede
        return res.status(500).json({ error: 'Erro ao consultar os dados de rastreio. Tente novamente mais tarde.' });
    }
};
