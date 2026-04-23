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
    // Verificamos o cargo do utilizador que foi guardado no req.user pelo middleware 'authenticate'
    // ⚠️ Se o teu token guarda o cargo com outro nome (ex: req.user.cargo ou req.user.department), deves alterar aqui!
    const userRole = req.user?.role; 

    // Se o utilizador não tiver cargo, ou se o seu cargo não estiver na lista de permitidos, bloqueamos.
    if (!userRole || !allowedRoles.includes(userRole)) {
      return res.status(403).json({ 
        error: 'Acesso negado. Esta ação é restrita a departamentos autorizados.' 
      });
    }
    
    // Se o cargo estiver correto, deixamos o pedido passar para a próxima função (o nosso controller de preços).
    next();
  };
};
