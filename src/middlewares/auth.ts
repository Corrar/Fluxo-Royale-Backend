import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta';

export const authenticate = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token necessário' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
};

/**
 * Middleware para verificar se o utilizador tem uma das roles (cargos) permitidas.
 * Exemplo de uso: authorizeRole(['financeiro', 'admin'])
 */
export const authorizeRole = (allowedRoles: string[]) => {
  return (req: any, res: any, next: any) => {
    // 1. Transformamos o cargo do utilizador em minúsculas para evitar erros de digitação na Base de Dados
    // Usamos o operador '?' (optional chaining) para evitar erros caso a role não exista no token
    const userRole = req.user?.role?.toLowerCase(); 

    // 2. Transformamos a nossa lista de permitidos em minúsculas também
    const safeAllowedRoles = allowedRoles.map(role => role.toLowerCase());

    // Se o utilizador não tiver cargo, ou se o seu cargo não estiver na lista de permitidos, bloqueamos.
    if (!userRole || !safeAllowedRoles.includes(userRole)) {
      return res.status(403).json({ 
        // Adicionei qual é a role atual na mensagem de erro, para facilitar se precisares de investigar!
        error: `Acesso negado. O seu cargo atual (${req.user?.role || 'Nenhum'}) não tem permissão para esta ação.` 
      });
    }
    
    // Se o cargo estiver correto, deixamos o pedido passar para a próxima função (o nosso controller de preços).
    next();
  };
};
