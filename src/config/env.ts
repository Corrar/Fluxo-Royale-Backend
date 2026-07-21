// Configuração central de segredos. Evita que o JWT_SECRET fique duplicado
// (e possa divergir) entre auth, socket e controllers.

const FALLBACK_JWT = 'sua-chave-secreta';

export const JWT_SECRET = process.env.JWT_SECRET || FALLBACK_JWT;

// Aviso gritante no boot se o servidor estiver a usar o segredo padrão: nesse
// caso qualquer pessoa consegue forjar um token de admin. DEFINA JWT_SECRET
// (um valor longo e aleatório) nas variáveis de ambiente do Render.
if (JWT_SECRET === FALLBACK_JWT) {
  console.error('🚨 SEGURANÇA: JWT_SECRET não está definido! Usando segredo padrão inseguro. Configure JWT_SECRET no ambiente IMEDIATAMENTE.');
}
