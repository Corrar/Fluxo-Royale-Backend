export const validatePositiveItems = (items: any[]) => {
  if (!items || !Array.isArray(items) || items.length === 0) {
    throw new Error('Lista de itens inválida ou vazia.');
  }
  for (const item of items) {
    const qty = Number(item.quantity || item.quantity_requested || item.qty_requested || item.quantity_out);
    if (isNaN(qty) || qty <= 0) {
      throw new Error(`Tentativa de manipulação detectada: Quantidade inválida (${qty}). Apenas valores positivos são permitidos.`);
    }
  }
};