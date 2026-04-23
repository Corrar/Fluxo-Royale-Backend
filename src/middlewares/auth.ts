import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta';

export const authenticate = (req: any, res: any, next: any) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Token necessário' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    // Agora o req.user conterá o ID, Email e a ROLE (cargo) vinda do token
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
    // 🛡️ .toLowerCase() ignora maiúsculas e .trim() remove espaços extras (ex: "Financeiro " -> "financeiro")
    const userRole = req.user?.role?.toLowerCase().trim(); 
    const safeAllowedRoles = allowedRoles.map(role => role.toLowerCase().trim());

    // Se o utilizador não tiver cargo no token, ou se o seu cargo não estiver na lista permitida
    if (!userRole || !safeAllowedRoles.includes(userRole)) {
      return res.status(403).json({ 
        error: `Acesso negado. O seu cargo atual (${req.user?.role || 'Nenhum'}) não tem permissão para esta ação.` 
      });
    }
    
    // Se estiver tudo correto, permite a execução da função seguinte (ex: updateProductPrices)
    next();
  };
};
