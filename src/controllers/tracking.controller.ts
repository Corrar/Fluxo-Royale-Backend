import { Request, Response } from 'express';

export const trackPackage = async (req: Request, res: Response) => {
    const { code } = req.params;

    if (!code) {
        return res.status(400).json({ error: 'Código de rastreio é obrigatório.' });
    }

    try {
        // Usamos a API pública do Link&Track para fugir do bloqueio de IP dos Correios no Render
        const url = `https://api.linketrack.com/track/json?user=teste&token=1abcd00b2731640e886fb41a8a9671ad1434c599dbaa0a0de9a5aa619f29a83f&codigo=${code}`;
        
        // O Node.js moderno já tem o fetch nativo, igual ao navegador
        const response = await fetch(url);
        
        if (!response.ok) {
            throw new Error('Falha na API de rastreio externa (Link&Track)');
        }

        const data = await response.json();

        // Se a encomenda não existir ou ainda não tiver sido postada
        if (!data.eventos || data.eventos.length === 0) {
             return res.status(200).json({ eventos: [] });
        }

        // O Link&Track devolve num formato ligeiramente diferente.
        // Vamos formatar para o exato padrão que o seu Frontend (React) já espera.
        const eventosFormatados = data.eventos.map((evt: any) => {
            
            // O Link&Track devolve a data como "DD/MM/YYYY" e hora "HH:MM". 
            // O React precisa do formato ISO: "YYYY-MM-DDTHH:MM:00"
            const [dia, mes, ano] = evt.data.split('/');
            const dataIso = `${ano}-${mes}-${dia}T${evt.hora}:00`;

            return {
                descricao: evt.status,
                dtHrCriado: dataIso,
                unidade: {
                    tipo: "Local",
                    endereco: {
                        cidade: evt.local, // Ex: "SAO PAULO - SP"
                        uf: ""
                    }
                }
            };
        });

        // Devolvemos o array formatado. O React faz: response.data.eventos
        res.status(200).json({ eventos: eventosFormatados });

    } catch (error) {
        console.error('Erro ao buscar rastreio:', error);
        res.status(500).json({ error: 'Erro ao consultar os dados de rastreio. Tente novamente mais tarde.' });
    }
};
