// Declara o contexto de auditoria da transação atual: o trigger da tabela
// stock (fn_log_stock_movement) lê estes valores e carimba cada movimento
// de estoque com a ação, o usuário e o documento de origem.
//
// IMPORTANTE: chamar sempre DEPOIS do BEGIN — set_config com is_local=true
// vale apenas dentro da transação corrente.
export const setStockAudit = async (
  client: any,
  action: string,
  userId: string | null | undefined,
  source?: string | null
) => {
  try {
    await client.query(
      `SELECT set_config('fluxo.audit_action', $1, true),
              set_config('fluxo.audit_user', $2, true),
              set_config('fluxo.audit_source', $3, true)`,
      [action || '', userId || '', source || '']
    );
  } catch (err) {
    // Nunca deixar a auditoria derrubar a operação principal
    console.error('Falha ao definir contexto de auditoria de estoque:', err);
  }
};
