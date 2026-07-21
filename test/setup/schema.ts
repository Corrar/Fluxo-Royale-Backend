// Schema mínimo das tabelas de estoque para os testes de integração (pg-mem).
// Cobre as colunas usadas pelos fluxos de estoque; não é o schema completo de
// produção, apenas o suficiente para exercitar reservas, débitos e devoluções.

export const applySchema = async (pool: any) => {
  await pool.query(`
    CREATE TABLE profiles (
      id TEXT PRIMARY KEY,
      name TEXT,
      role TEXT,
      sector TEXT
    );

    CREATE TABLE users (
      id TEXT PRIMARY KEY,
      email TEXT,
      encrypted_password TEXT,
      is_active BOOLEAN DEFAULT true,
      total_minutes NUMERIC DEFAULT 0,
      last_active TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE products (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      sku TEXT,
      name TEXT,
      description TEXT,
      unit TEXT,
      min_stock NUMERIC DEFAULT 0,
      unit_price NUMERIC DEFAULT 0,
      sales_price NUMERIC DEFAULT 0,
      tags TEXT,
      is_3d BOOLEAN DEFAULT false,
      production_minutes NUMERIC DEFAULT 0,
      filament_grams NUMERIC DEFAULT 0,
      image_url TEXT,
      active BOOLEAN DEFAULT true,
      purchase_status TEXT,
      purchase_note TEXT,
      delivery_forecast TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE stock (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      product_id UUID UNIQUE,
      quantity_on_hand NUMERIC DEFAULT 0,
      quantity_reserved NUMERIC DEFAULT 0,
      critical_since TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE client_services (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      op_code TEXT,
      status TEXT DEFAULT 'aberta'
    );

    CREATE TABLE requests (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      requester_id TEXT,
      sector TEXT,
      status TEXT,
      client_service_id UUID,
      rejection_reason TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE request_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      request_id UUID,
      product_id UUID,
      custom_product_name TEXT,
      quantity_requested NUMERIC,
      quantity_delivered NUMERIC,
      quantity_returned NUMERIC,
      observation TEXT,
      client_service TEXT,
      unit_price NUMERIC
    );

    CREATE TABLE separations (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      destination TEXT,
      client_name TEXT,
      production_order TEXT,
      status TEXT,
      type TEXT,
      client_service_id UUID,
      sent_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE separation_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      separation_id UUID,
      product_id UUID,
      qty_requested NUMERIC,
      quantity NUMERIC,
      observation TEXT,
      unit_price NUMERIC
    );

    CREATE TABLE separation_returns (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      separation_id UUID,
      product_id UUID,
      quantity NUMERIC,
      status TEXT
    );

    CREATE TABLE replenishments (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      order_number TEXT,
      client_name TEXT,
      city_state TEXT,
      status TEXT,
      total_value NUMERIC DEFAULT 0,
      shipping_info TEXT,
      tracking_code TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE replenishment_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      replenishment_id UUID,
      product_id UUID,
      qty_requested NUMERIC,
      quantity NUMERIC,
      unit_price NUMERIC
    );

    CREATE TABLE travel_orders (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      technicians TEXT,
      city TEXT,
      status TEXT,
      created_by TEXT,
      created_at TIMESTAMPTZ DEFAULT now(),
      updated_at TIMESTAMPTZ
    );

    CREATE TABLE travel_order_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      travel_order_id UUID,
      product_id UUID,
      quantity_out NUMERIC,
      quantity_returned NUMERIC,
      status TEXT
    );

    CREATE TABLE demands_3d (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      product_id UUID,
      request_id UUID,
      quantity NUMERIC,
      op_number TEXT,
      priority TEXT,
      notes TEXT,
      status TEXT DEFAULT 'Pendente',
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE op_returns (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      client_service_id UUID,
      product_id UUID,
      quantity NUMERIC,
      user_id TEXT,
      observation TEXT
    );

    CREATE TABLE productions_3d (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      product_id UUID,
      demand_id UUID,
      quantity NUMERIC,
      operator_id TEXT,
      total_minutes NUMERIC,
      filament_grams NUMERIC,
      date TIMESTAMPTZ
    );

    CREATE TABLE audit_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id TEXT,
      action TEXT,
      details TEXT,
      ip_address TEXT,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE xml_logs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      file_name TEXT,
      success BOOLEAN,
      total_items NUMERIC,
      created_at TIMESTAMPTZ DEFAULT now()
    );

    CREATE TABLE xml_items (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      xml_log_id UUID,
      product_id UUID,
      quantity NUMERIC
    );
  `);
};

// Cria um produto + linha de stock e devolve o product_id.
export const seedProduct = async (
  pool: any,
  opts: { sku?: string; name?: string; onHand?: number; reserved?: number; is3d?: boolean; unitPrice?: number; tags?: string } = {}
): Promise<string> => {
  const { rows } = await pool.query(
    `INSERT INTO products (sku, name, unit, is_3d, unit_price, tags, active)
     VALUES ($1, $2, 'un', $3, $4, $5, true) RETURNING id`,
    [opts.sku || 'SKU-1', opts.name || 'Produto Teste', opts.is3d || false, opts.unitPrice ?? 10, opts.tags ?? null]
  );
  const productId = rows[0].id;
  await pool.query(
    `INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved) VALUES ($1, $2, $3)`,
    [productId, opts.onHand ?? 0, opts.reserved ?? 0]
  );
  return productId;
};

export const getStock = async (pool: any, productId: string) => {
  const { rows } = await pool.query('SELECT quantity_on_hand, quantity_reserved FROM stock WHERE product_id = $1', [productId]);
  return { onHand: Number(rows[0].quantity_on_hand), reserved: Number(rows[0].quantity_reserved) };
};
