import express from 'express';
import cors from 'cors';
import { pool } from './db';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { Server } from 'socket.io';
import webpush from 'web-push'; 

const app = express();

// --- 1. CONFIGURAÇÃO DO SERVIDOR HTTP + SOCKET.IO ---
const httpServer = createServer(app);

// Configuração de segurança de Proxy
app.set('trust proxy', 1);

// Segurança de Headers
app.use(helmet());

// --- CONFIGURAÇÃO WEB PUSH ---
const publicVapidKey = process.env.VAPID_PUBLIC_KEY || 'SUA_PUBLIC_KEY_SE_NAO_TIVER_ENV';
const privateVapidKey = process.env.VAPID_PRIVATE_KEY || 'SUA_PRIVATE_KEY_SE_NAO_TIVER_ENV';
const vapidSubject = process.env.VAPID_SUBJECT || 'mailto:admin@fluxoroyale.com';

if (process.env.VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(vapidSubject, publicVapidKey, privateVapidKey);
  console.log("✅ Web Push Configurado!");
} else {
  console.warn("⚠️ AVISO: VAPID Keys não configuradas. Notificações Push não funcionarão.");
}

// --- 2. CONFIGURAÇÃO ROBUSTA DE CORS ---
const allowedOrigins = [
  'http://localhost:5173',        
  'http://localhost:3000',        
  'https://fluxo-royale.vercel.app',
  'https://fluxoroyale21.vercel.app'
];

const corsOptions = {
  origin: function (origin: any, callback: any) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.indexOf(origin) !== -1) return callback(null, true);
    if (origin.startsWith('http://localhost') || origin.startsWith('http://192.168.')) {
        return callback(null, true);
    }
    return callback(new Error('Bloqueio CORS: Origem não permitida'), false);
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};

app.use(cors(corsOptions));
app.use(express.json());

// Inicializa o Socket.io
const io = new Server(httpServer, {
  cors: corsOptions
});

app.use((req: any, res, next) => {
  req.io = io;
  next();
});

io.on('connection', (socket) => {
  console.log(`⚡ Cliente Socket conectado: ${socket.id}`);

  socket.on('join_room', (role) => {
    socket.join(role);
  });

  socket.on('disconnect', () => {
    // console.log('Cliente desconectou');
  });
});

// --- FUNÇÃO AUXILIAR: ENVIAR PUSH NOTIFICATION ---
const sendPushNotificationToRole = async (role: string, title: string, message: string, url: string = '/requests') => {
  try {
    let query = `
      SELECT ps.subscription 
      FROM push_subscriptions ps
      JOIN profiles p ON ps.user_id::uuid = p.id
      WHERE p.role = $1
    `;
    
    if (role === 'almoxarife') {
       query = `
        SELECT ps.subscription 
        FROM push_subscriptions ps
        JOIN profiles p ON ps.user_id::uuid = p.id
        WHERE p.role IN ('almoxarife', 'admin')
       `;
    }

    const { rows } = await pool.query(query, role === 'almoxarife' ? [] : [role]);
    
    console.log(`📡 Enviando Push para ${rows.length} dispositivos (${role})...`);

    const payload = JSON.stringify({
      title: title,
      body: message,
      url: url,
      icon: '/favicon.png',
      tag: 'fluxo-alert-requests', 
      renotify: true,
      priority: 'high'
    });

    const promises = rows.map(async (row) => {
      try {
        const sub = row.subscription; 
        await webpush.sendNotification(sub, payload);
      } catch (err: any) {
        if (err.statusCode === 410 || err.statusCode === 404) {
          console.log("Inscrição antiga/inválida detectada.");
        } else {
          console.error("Erro no envio do push:", err);
        }
      }
    });

    await Promise.all(promises);

  } catch (error) {
    console.error("Falha geral no envio de Push:", error);
  }
};

// --- LOGS DE AUDITORIA ---
const createLog = async (userId: string | null, action: string, details: object, ip: string) => {
  try {
    const insertResult = await pool.query(
      `INSERT INTO audit_logs (user_id, action, details, ip_address) 
        VALUES ($1, $2, $3, $4) RETURNING id`,
      [userId, action, JSON.stringify(details), ip]
    );

    const newLogId = insertResult.rows[0].id;

    const fullLogQuery = `
      SELECT 
        a.id, 
        a.action, 
        a.details, 
        a.created_at, 
        a.ip_address,
        COALESCE(p.name, u.email, 'Usuário Removido') as user_name, 
        COALESCE(p.role::text, 'removido') as user_role
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN profiles p ON u.id = p.id
      WHERE a.id = $1
    `;
    
    const fullLogResult = await pool.query(fullLogQuery, [newLogId]);
    const newLogData = fullLogResult.rows[0];

    io.to('admin').emit('new_audit_log', newLogData);

  } catch (err) {
    console.error("Falha ao criar log de auditoria:", err);
  }
};

// --- RATE LIMITS ---
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300, 
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(globalLimiter);

const authLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, 
  max: 20, 
  message: 'Muitas tentativas erradas. Sua conta está temporariamente bloqueada.',
  standardHeaders: true, 
  legacyHeaders: false,
});

const JWT_SECRET = process.env.JWT_SECRET || 'sua-chave-secreta';

const authenticate = (req: any, res: any, next: any) => {
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

// ==========================================
// ROTAS DE SEPARAÇÃO (NOVO FLUXO 2.1)
// ==========================================

// 1. Listar Separações (OPs e Manuais) com detalhes de estoque e devoluções
app.get('/separations', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*,
        (SELECT json_agg(json_build_object(
          'id', si.id, 
          'product_id', si.product_id, 
          'quantity', si.quantity, 
          'qty_requested', si.qty_requested,
          'products', json_build_object(
             'name', p.name, 
             'sku', p.sku, 
             'unit', p.unit,
             'unit_price', p.unit_price,
             'stock', json_build_object(
                'quantity_on_hand', COALESCE(st.quantity_on_hand, 0), 
                'quantity_reserved', COALESCE(st.quantity_reserved, 0)
             )
          )
        )) FROM separation_items si 
           JOIN products p ON si.product_id = p.id 
           LEFT JOIN stock st ON p.id = st.product_id 
           WHERE si.separation_id = s.id
        ) as items,
        (SELECT json_agg(json_build_object(
          'id', sr.id, 
          'product_id', sr.product_id, 
          'quantity', sr.quantity, 
          'status', sr.status, 
          'product_name', p.name
        )) FROM separation_returns sr 
           JOIN products p ON sr.product_id = p.id 
           WHERE sr.separation_id = s.id
        ) as returns
      FROM separations s 
      ORDER BY s.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar separações' });
  }
});

// 2. Criar Nova Separação (Ordem de Produção)
app.post('/separations', authenticate, async (req, res) => {
  const { client_name, production_order, destination, items } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const sepRes = await client.query(
      `INSERT INTO separations (destination, client_name, production_order, status, type) 
       VALUES ($1, $2, $3, 'pendente', 'op') RETURNING id`,
      [destination, client_name, production_order]
    );
    const separationId = sepRes.rows[0].id;

    for (const item of items) {
      await client.query(
        `INSERT INTO separation_items (separation_id, product_id, qty_requested, quantity) VALUES ($1, $2, $3, 0)`,
        [separationId, item.product_id, item.quantity]
      );
    }
    await client.query('COMMIT');
    io.emit('separations_update');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally { client.release(); }
});

// 2.5 Editar Separação Existente (Apenas Almoxarife e Admin)
app.put('/separations/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const userId = (req as any).user.id;
  const { production_order, client_name, destination, items } = req.body;

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    // 1. Validação de Segurança: Apenas Admin/Almoxarife podem editar
    const userCheck = await client.query('SELECT role FROM profiles WHERE id = $1', [userId]);
    const role = userCheck.rows[0]?.role;
    if (role !== 'admin' && role !== 'almoxarife') {
      throw new Error('Apenas almoxarife e admin podem editar pedidos.');
    }

    // 2. Validação de Status: Apenas editar o que não foi finalizado/entregue
    const sepCheck = await client.query('SELECT status FROM separations WHERE id = $1', [id]);
    if (sepCheck.rows.length === 0) throw new Error('Pedido não encontrado.');
    const currentStatus = sepCheck.rows[0].status;
    if (currentStatus !== 'pendente' && currentStatus !== 'em_separacao') {
      throw new Error('Apenas pedidos pendentes ou em separação podem ser editados.');
    }

    // 3. Atualizar dados principais do pedido
    await client.query(
      `UPDATE separations 
       SET production_order = COALESCE($1, production_order), 
           client_name = COALESCE($2, client_name), 
           destination = COALESCE($3, destination) 
       WHERE id = $4`,
      [production_order, client_name, destination, id]
    );

    // 4. Buscar os itens que já existem no banco para este pedido
    const existingItemsRes = await client.query('SELECT id, product_id, quantity FROM separation_items WHERE separation_id = $1', [id]);
    const existingItems = existingItemsRes.rows;

    // Criar um mapa dos itens novos que vieram do Frontend para facilitar a busca
    const newItemsMap = new Map(items.map((i: any) => [i.product_id, i]));

    // 5. Sincronizar itens antigos vs novos
    for (const oldItem of existingItems) {
      if (!newItemsMap.has(oldItem.product_id)) {
        // Cenario A: O item foi REMOVIDO da lista pelo Almoxarife.
        // Se já existia algo separado (reservado), precisamos devolver ao estoque disponível!
        const separatedQty = parseFloat(oldItem.quantity || 0);
        if (separatedQty > 0) {
          await client.query(
            `UPDATE stock 
             SET quantity_on_hand = quantity_on_hand + $1, 
                 quantity_reserved = GREATEST(0, quantity_reserved - $1) 
             WHERE product_id = $2`,
            [separatedQty, oldItem.product_id]
          );
        }
        // Excluir a linha do item no pedido
        await client.query('DELETE FROM separation_items WHERE id = $1', [oldItem.id]);
      } else {
        // Cenario B: O item se MANTEVE, vamos atualizar a quantidade SOLICITADA.
        // CORREÇÃO APLICADA AQUI: Definimos newItem como "any" para evitar o erro TS18046.
        const newItem: any = newItemsMap.get(oldItem.product_id);
        await client.query(
          'UPDATE separation_items SET qty_requested = $1 WHERE id = $2',
          [newItem.quantity, oldItem.id]
        );
      }
    }

    // 6. Inserir os NOVOS itens que não existiam antes no pedido
    for (const item of items) {
      const exists = existingItems.some((old: any) => old.product_id === item.product_id);
      if (!exists) {
        // Cenario C: Item NOVO. Adiciona com quantity (separado) = 0
        await client.query(
          `INSERT INTO separation_items (separation_id, product_id, qty_requested, quantity) 
           VALUES ($1, $2, $3, 0)`,
          [id, item.product_id, item.quantity]
        );
      }
    }

    // 7. Salvar Log de Auditoria
    await createLog(userId, 'EDIT_SEPARATION', { separationId: id, details: 'Itens editados via painel' }, req.ip || '127.0.0.1');
    
    await client.query('COMMIT');

    // 8. Atualizar painéis abertos
    if ((req as any).io) {
      (req as any).io.emit('separations_update');
    } else {
      io.emit('separations_update');
    }

    res.json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});


// 3. Autorizar/Processar (Reserva e Entrega) - O Coração do Fluxo 2.1
app.put('/separations/:id/authorize', authenticate, async (req, res) => {
  const { id } = req.params;
  const { items, action } = req.body; // 'reservar' ou 'entregar'
  const userId = (req as any).user.id;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    for (const item of items) {
      const oldItem = await client.query('SELECT quantity, product_id FROM separation_items WHERE id = $1', [item.id]);
      if (oldItem.rows.length > 0) {
        const oldQty = parseFloat(oldItem.rows[0].quantity || 0);
        const newQty = parseFloat(item.quantity);
        const productId = oldItem.rows[0].product_id;
        const diff = newQty - oldQty;

        // Atualiza a quantidade "separada" no item da separação
        await client.query('UPDATE separation_items SET quantity = $1 WHERE id = $2', [newQty, item.id]);

        if (action === 'reservar' && diff !== 0) {
          // Lógica de RESERVA: Move do Disponível para o Reservado
          if (diff > 0) {
            const st = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1 FOR UPDATE', [productId]);
            if (parseFloat(st.rows[0]?.quantity_on_hand || 0) < diff) throw new Error(`Estoque insuficiente para o produto ID ${productId}`);
          }
          await client.query(`UPDATE stock SET quantity_on_hand = quantity_on_hand - $1, quantity_reserved = quantity_reserved + $1 WHERE product_id = $2`, [diff, productId]);
        
        } else if (action === 'entregar') {
          // Lógica de ENTREGA: Baixa do Reservado.
          // Se entregou MENOS do que estava reservado (oldQty > newQty), a sobra volta pro Disponível.
          const sobra = oldQty - newQty;
          await client.query(`UPDATE stock SET quantity_reserved = GREATEST(0, quantity_reserved - $1), quantity_on_hand = quantity_on_hand + $2 WHERE product_id = $3`, [oldQty, sobra, productId]);
        }
      }
    }

    const newStatus = action === 'entregar' ? 'entregue' : 'em_separacao';
    await client.query(`UPDATE separations SET status = $1 ${action === 'entregar' ? ', sent_at = NOW()' : ''} WHERE id = $2`, [newStatus, id]);
    
    await createLog(userId, 'UPDATE_SEPARATION', { separationId: id, action }, req.ip || '127.0.0.1');
    await client.query('COMMIT');
    io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally { client.release(); }
});

// 4. Criar Intenção de Devolução (Return)
app.post('/separations/:id/return', authenticate, async (req, res) => {
  const { id } = req.params;
  const { items } = req.body;
  try {
    for (const item of items) {
      await pool.query(
        `INSERT INTO separation_returns (separation_id, product_id, quantity, status) VALUES ($1, $2, $3, 'pendente')`,
        [id, item.product_id, item.quantity]
      );
    }
    io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) { res.status(500).json({ error: 'Erro ao criar devolução' }); }
});

// 5. Aprovar/Rejeitar Devolução
app.put('/separations/returns/:returnId', authenticate, async (req, res) => {
  const { returnId } = req.params;
  const { status } = req.body; // 'aprovado' ou 'rejeitado'
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const ret = await client.query('SELECT * FROM separation_returns WHERE id = $1 FOR UPDATE', [returnId]);
    
    if (ret.rows.length === 0 || ret.rows[0].status !== 'pendente') throw new Error("Devolução já processada ou inexistente");
    
    await client.query('UPDATE separation_returns SET status = $1 WHERE id = $2', [status, returnId]);
    
    if (status === 'aprovado') {
      // Devolve ao estoque disponível
      await client.query('UPDATE stock SET quantity_on_hand = quantity_on_hand + $1 WHERE product_id = $2', [ret.rows[0].quantity, ret.rows[0].product_id]);
    }
    await client.query('COMMIT');
    io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(400).json({ error: error.message });
  } finally { client.release(); }
});

// 6. Excluir Separação
app.delete('/separations/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    // Nota: Em um cenário ideal, deveria verificar se há itens reservados antes de deletar e estorná-los.
    // Assumimos aqui que só se deleta OPs pendentes ou sem reservas ativas.
    await pool.query('DELETE FROM separations WHERE id = $1', [id]);
    io.emit('separations_update');
    res.json({ success: true });
  } catch (error: any) { res.status(500).json({ error: 'Erro ao excluir' }); }
});


// ==========================================
// OUTRAS ROTAS (EXISTENTES)
// ==========================================

// ROTA: SALVAR INSCRIÇÃO
app.post('/notifications/subscribe', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const { subscription } = req.body;

  if (!subscription || !subscription.endpoint) {
    return res.status(400).json({ error: 'Subscription inválida' });
  }

  try {
    await pool.query(
      `INSERT INTO push_subscriptions (user_id, subscription) VALUES ($1, $2)`,
      [userId, JSON.stringify(subscription)]
    );
    res.status(201).json({ success: true });
  } catch (error) {
    res.status(200).json({ success: true }); 
  }
});

// HEARTBEAT
app.put('/users/:id/heartbeat', authenticate, async (req, res) => {
  const { id } = req.params;
  try { 
    await pool.query(`
      UPDATE users 
      SET total_minutes = COALESCE(total_minutes, 0) + 1, last_active = NOW() 
      WHERE id = $1
    `, [id]);
    res.json({ success: true }); 
  } catch (error) { 
    res.json({ success: false }); 
  }
});

app.get('/admin/logs', authenticate, async (req, res) => {
  const requesterId = (req as any).user.id;
  const adminCheck = await pool.query("SELECT role FROM profiles WHERE id = $1", [requesterId]);
  
  if (adminCheck.rows[0]?.role !== 'admin') {
    return res.status(403).json({ error: 'Acesso negado.' });
  }

  try {
    const { action, user, startDate, endDate } = req.query;

    let query = `
      SELECT 
        a.id, 
        a.action, 
        a.details, 
        a.created_at, 
        a.ip_address,
        COALESCE(p.name, u.email, 'Usuário Removido') as user_name, 
        COALESCE(p.role::text, 'removido') as user_role
      FROM audit_logs a
      LEFT JOIN users u ON a.user_id = u.id
      LEFT JOIN profiles p ON u.id = p.id
      WHERE 1=1
    `;

    const params: any[] = [];
    let paramIndex = 1;

    if (action && action !== 'ALL') {
      query += ` AND a.action = $${paramIndex}`;
      params.push(action);
      paramIndex++;
    }

    if (user) {
      query += ` AND (p.name ILIKE $${paramIndex} OR u.email ILIKE $${paramIndex})`;
      params.push(`%${user}%`);
      paramIndex++;
    }

    if (startDate) {
      query += ` AND a.created_at >= $${paramIndex}`;
      params.push(`${startDate} 00:00:00`);
      paramIndex++;
    }

    if (endDate) {
      query += ` AND a.created_at <= $${paramIndex}`;
      params.push(`${endDate} 23:59:59`);
      paramIndex++;
    }

    query += ` ORDER BY a.created_at DESC LIMIT 100`;

    const { rows } = await pool.query(query, params);
    res.json(rows);
  } catch (error: any) {
    console.error("Erro logs:", error);
    res.status(500).json({ error: "Erro ao buscar logs" });
  }
});

app.get('/admin/permissions', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT role, page_key FROM role_permissions');
    const permissionsMap: Record<string, string[]> = {};
    rows.forEach((row: any) => {
      if (!permissionsMap[row.role]) {
        permissionsMap[row.role] = [];
      }
      permissionsMap[row.role].push(row.page_key);
    });
    res.json(permissionsMap);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar permissões' });
  }
});

app.post('/admin/permissions', authenticate, async (req, res) => {
  const { role, permissions } = req.body;
  const requesterId = (req as any).user.id;
  const adminCheck = await pool.query("SELECT role FROM profiles WHERE id = $1", [requesterId]);
  if (adminCheck.rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Apenas admins.' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM role_permissions WHERE role = $1', [role]);
    for (const page of permissions) {
      await client.query('INSERT INTO role_permissions (role, page_key) VALUES ($1, $2)', [role, page]);
    }
    await client.query('COMMIT');
    
    await createLog(requesterId, 'UPDATE_PERMISSIONS', { role_target: role, count: permissions.length }, req.ip || '127.0.0.1');
    io.to(role).emit('permissions_updated', permissions);

    res.json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: 'Erro ao salvar permissões' });
  } finally {
    client.release();
  }
});

// --- AUTH ---
app.post('/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    const user = rows[0];

    if (!user) return res.status(400).json({ error: 'Usuário não encontrado' });

    const validPassword = await bcrypt.compare(password, user.encrypted_password);
    if (!validPassword) return res.status(400).json({ error: 'Senha incorreta' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
    
    let { rows: profiles } = await pool.query('SELECT * FROM profiles WHERE id = $1', [user.id]);
    if (profiles.length === 0) {
      const defaultName = user.email.split('@')[0];
      const insertRes = await pool.query(
        `INSERT INTO profiles (id, name, role, sector) VALUES ($1, $2, 'setor', 'Geral') RETURNING *`,
        [user.id, defaultName]
      );
      profiles = insertRes.rows;
    }

    const permRes = await pool.query('SELECT page_key FROM role_permissions WHERE role = $1', [profiles[0].role]);
    const userPermissions = permRes.rows.map((r: any) => r.page_key);
    
    await createLog(user.id, 'LOGIN', { message: 'Login realizado' }, req.ip || '127.0.0.1');

    res.json({ token, user, profile: profiles[0], permissions: userPermissions });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/auth/register', async (req, res) => {
  const { email, password, name, role, sector } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const userCheck = await client.query('SELECT id FROM users WHERE email = $1', [email]);
    if (userCheck.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'ID de usuário já está em uso' });
    }
    const salt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(password, salt);
    
    const userRes = await client.query(
      'INSERT INTO users (email, encrypted_password) VALUES ($1, $2) RETURNING id',
      [email, encryptedPassword]
    );
    const newUserId = userRes.rows[0].id;

    await client.query(
      `INSERT INTO profiles (id, name, role, sector) VALUES ($1, $2, $3, $4)
       ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, role = EXCLUDED.role, sector = EXCLUDED.sector`,
      [newUserId, name, role, sector]
    );

    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.get('/users', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        u.id, 
        u.email, 
        COALESCE(p.name, u.email) as name, 
        COALESCE(p.role, 'setor') as role, 
        COALESCE(p.sector, '-') as sector, 
        u.created_at,
        u.total_minutes,
        u.last_active
      FROM users u 
      LEFT JOIN profiles p ON u.id = p.id 
      ORDER BY u.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar usuários' });
  }
});

app.put('/users/:id/role', authenticate, async (req, res) => {
  const { id } = req.params;
  const { role } = req.body;
  try {
    await pool.query('UPDATE profiles SET role = $1 WHERE id = $2', [role, id]);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao atualizar função' });
  }
});

app.delete('/users/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query('DELETE FROM users WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao excluir usuário' });
  }
});

// --- PRODUTOS ---
app.get('/products', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        p.id,
        p.sku,
        p.name,
        p.description,
        p.unit,
        p.tags, 
        p.unit_price, 
        p.sales_price,
        p.min_stock,
        p.active,
        json_build_object(
          'quantity_on_hand', COALESCE(s.quantity_on_hand, 0),
          'quantity_reserved', COALESCE(s.quantity_reserved, 0),
          'quantity_open', (
             SELECT COALESCE(SUM(ri.quantity_requested), 0)
             FROM request_items ri
             JOIN requests r ON ri.request_id = r.id
             WHERE ri.product_id = p.id AND r.status = 'aberto'
          )
        ) as stock
      FROM products p
      LEFT JOIN stock s ON p.id = s.product_id
      WHERE p.active = true
      ORDER BY p.name ASC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/products/low-stock', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT 
        p.id, p.sku, p.name, p.unit, p.min_stock, 
        p.purchase_status, p.purchase_note, p.delivery_forecast,
        COALESCE(s.quantity_on_hand, 0) as quantity, 
        COALESCE(s.quantity_reserved, 0) as quantity_reserved,
        s.critical_since, 
        (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) as disponivel,
        (
          SELECT COALESCE(SUM(ri.quantity_requested), 0)
          FROM request_items ri
          JOIN requests r ON ri.request_id = r.id
          WHERE ri.product_id = p.id AND r.status IN ('aberto', 'aprovado')
        ) as demanda_reprimida
      FROM products p
      LEFT JOIN stock s ON p.id = s.product_id
      WHERE p.min_stock IS NOT NULL 
        AND p.active = true
        AND (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) < CAST(NULLIF(CAST(p.min_stock AS TEXT), '') AS NUMERIC)
      ORDER BY (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) ASC
    `);
    res.json(rows);
  } catch (error: any) { 
    console.error("ERRO LOW-STOCK:", error);
    res.status(500).json({ error: 'Erro ao buscar estoque baixo' }); 
  }
});

app.post('/products', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price, tags } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const productRes = await client.query(
      'INSERT INTO products (sku, name, description, unit, min_stock, unit_price, sales_price, tags) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *',
      [sku, name, description, unit, min_stock, unit_price || 0, sales_price || 0, JSON.stringify(tags || [])]
    );
    const newProduct = productRes.rows[0];

    const initialQty = quantity ? parseFloat(quantity) : 0;
    await client.query(
      `INSERT INTO stock (product_id, quantity_on_hand, quantity_reserved) 
        VALUES ($1, $2, 0)
        ON CONFLICT (product_id) 
        DO UPDATE SET quantity_on_hand = COALESCE(stock.quantity_on_hand, 0) + EXCLUDED.quantity_on_hand`,
      [newProduct.id, initialQty]
    );

    if (initialQty > 0) {
      const logRes = await client.query("INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", ['Estoque Inicial - Cadastro', true, 1]);
      await client.query("INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", [logRes.rows[0].id, newProduct.id, initialQty]);
    }
    
    await client.query('COMMIT');
    await createLog(userId, 'CREATE_PRODUCT', { sku, name, initialQty }, req.ip || '127.0.0.1');

    res.status(201).json(newProduct);
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.put('/products/:id', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  const { sku, name, description, unit, min_stock, quantity, unit_price, sales_price, tags } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const { rows } = await client.query(
      `UPDATE products SET 
          sku = COALESCE($1, sku), 
          name = COALESCE($2, name), 
          description = COALESCE($3, description), 
          unit = COALESCE($4, unit), 
          min_stock = COALESCE($5, min_stock),
          unit_price = COALESCE($6, unit_price),
          sales_price = COALESCE($7, sales_price),
          tags = COALESCE($8, tags)
        WHERE id = $9 RETURNING *`,
      [sku || null, name || null, description || null, unit || null, min_stock || null, unit_price || null, sales_price || null, tags ? JSON.stringify(tags) : null, id]
    );

    if (rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Produto não encontrado' });
    }
    
    if (quantity !== undefined && quantity !== "") {
      await client.query('UPDATE stock SET quantity_on_hand = $1 WHERE product_id = $2', [parseFloat(quantity), id]);
    }
    
    await client.query('COMMIT');
    await createLog(userId, 'UPDATE_PRODUCT', { id, name, changes: req.body }, req.ip || '127.0.0.1');

    res.json(rows[0]);
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message });
  } finally {
    client.release();
  }
});

app.put('/products/:id/purchase-info', authenticate, async (req, res) => {
  const { id } = req.params;
  const { purchase_status, purchase_note, delivery_forecast } = req.body;
  try {
    await pool.query(
      'UPDATE products SET purchase_status = $1, purchase_note = $2, delivery_forecast = $3 WHERE id = $4',
      [purchase_status, purchase_note, delivery_forecast || null, id]
    );
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao atualizar info de compra' });
  }
});

app.delete('/products/:id', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  try {
    await pool.query('UPDATE products SET active = false WHERE id = $1', [id]);
    await createLog(userId, 'DELETE_PRODUCT', { id, message: 'Produto arquivado' }, req.ip || '127.0.0.1');
    res.json({ message: 'Produto arquivado com sucesso' });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// --- TASKS ---
app.get('/tasks', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM tasks ORDER BY created_at DESC');
    
    const formattedRows = rows.map((task: any) => ({
      ...task,
      checklist: task.checklist || [],
      tags: task.tags || [],
      imageUrl: task.image_url,
      dueDate: task.due_date,
      createdAt: task.created_at,
      completedAt: task.completed_at
    }));
    
    res.json(formattedRows);
  } catch (error: any) {
    console.error("Erro buscar tarefas:", error);
    res.status(500).json({ error: 'Erro ao buscar tarefas' });
  }
});

app.post('/tasks', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const userCheck = await pool.query('SELECT role FROM profiles WHERE id = $1', [userId]);
  const role = userCheck.rows[0]?.role;
  
  if (role !== 'admin' && role !== 'gerente') {
    return res.status(403).json({ error: 'Sem permissão para criar tarefas.' });
  }

  const { title, description, category, priority, checklist, tags, imageUrl, dueDate } = req.body;
  
  try {
    const { rows } = await pool.query(
      `INSERT INTO tasks (title, description, category, priority, checklist, tags, image_url, due_date) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
        RETURNING *`,
      [
        title, 
        description, 
        category || 'blue', 
        priority, 
        JSON.stringify(checklist || []), 
        JSON.stringify(tags || []),
        imageUrl || null,
        dueDate || null
      ]
    );

    const newTask = {
      ...rows[0],
      checklist: rows[0].checklist || [],
      tags: rows[0].tags || [],
      imageUrl: rows[0].image_url,
      dueDate: rows[0].due_date,
      createdAt: rows[0].created_at,
      completedAt: rows[0].completed_at
    };

    if ((req as any).io) {
      (req as any).io.emit('tasks_updated'); 
    }

    res.status(201).json(newTask);
  } catch (error: any) {
    console.error("Erro criar tarefa:", error);
    res.status(500).json({ error: 'Erro ao criar tarefa' });
  }
});

app.put('/tasks/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  
  const userId = (req as any).user.id;
  const userCheck = await pool.query('SELECT role FROM profiles WHERE id = $1', [userId]);
  const role = userCheck.rows[0]?.role;
  
  if (role !== 'admin' && role !== 'gerente') {
    return res.status(403).json({ error: 'Sem permissão para editar tarefas.' });
  }

  const { title, description, category, priority, checklist, completed, tags, imageUrl, dueDate } = req.body;

  try {
    const fields: string[] = [];
    const values: any[] = [];
    let idx = 1;

    if (title !== undefined) { fields.push(`title = $${idx++}`); values.push(title); }
    if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }
    if (category !== undefined) { fields.push(`category = $${idx++}`); values.push(category); }
    if (priority !== undefined) { fields.push(`priority = $${idx++}`); values.push(priority); }
    if (checklist !== undefined) { fields.push(`checklist = $${idx++}`); values.push(JSON.stringify(checklist)); }
    if (tags !== undefined) { fields.push(`tags = $${idx++}`); values.push(JSON.stringify(tags)); }
    if (imageUrl !== undefined) { fields.push(`image_url = $${idx++}`); values.push(imageUrl); }
    if (dueDate !== undefined) { fields.push(`due_date = $${idx++}`); values.push(dueDate); }
    
    if (completed !== undefined) {
       fields.push(`completed = $${idx++}`); values.push(completed);
       if (completed) {
           fields.push(`completed_at = NOW()`);
       } else {
           fields.push(`completed_at = NULL`);
       }
    }

    values.push(id);
    
    if (fields.length === 0) return res.status(400).json({ error: 'Nenhum campo para atualizar' });

    const { rows } = await pool.query(
      `UPDATE tasks SET ${fields.join(', ')} WHERE id = $${idx} RETURNING *`,
      values
    );

    if (rows.length === 0) return res.status(404).json({ error: 'Tarefa não encontrada' });

    if ((req as any).io) {
      (req as any).io.emit('tasks_updated');
    }

    res.json(rows[0]);
  } catch (error: any) {
    console.error("Erro update task:", error);
    res.status(500).json({ error: 'Erro ao atualizar tarefa' });
  }
});

app.delete('/tasks/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  
  const userId = (req as any).user.id;
  const userCheck = await pool.query('SELECT role FROM profiles WHERE id = $1', [userId]);
  const role = userCheck.rows[0]?.role;
  
  if (role !== 'admin' && role !== 'gerente') {
    return res.status(403).json({ error: 'Sem permissão para excluir tarefas.' });
  }

  try {
    await pool.query('DELETE FROM tasks WHERE id = $1', [id]);
    
    if ((req as any).io) {
      (req as any).io.emit('tasks_updated');
    }
    
    res.json({ success: true });
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao excluir tarefa' });
  }
});

// --- ESTOQUE E REQUESTS ---
app.get('/stock', authenticate, async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT s.*, json_build_object(
        'id', p.id, 
        'name', p.name, 
        'sku', p.sku, 
        'unit', p.unit, 
        'min_stock', p.min_stock, 
        'unit_price', p.unit_price, 
        'sales_price', p.sales_price,
        'tags', p.tags
      ) as products 
      FROM stock s JOIN products p ON s.product_id = p.id 
      WHERE p.active = true
      ORDER BY s.created_at DESC
    `);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar estoque' });
  }
});

app.put('/stock/:id', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const { id } = req.params;
  const { quantity_on_hand } = req.body;
  
  try {
    const userCheck = await pool.query('SELECT role, sector FROM profiles WHERE id = $1', [userId]);
    const userProfile = userCheck.rows[0];
    
    const isMaster = userProfile.role === 'admin' || userProfile.role === 'almoxarife';
    
    if (!isMaster) {
       const stockItem = await pool.query(`
          SELECT p.tags 
          FROM stock s 
          JOIN products p ON s.product_id = p.id 
          WHERE s.id = $1
       `, [id]);
       
       const tags = stockItem.rows[0]?.tags || [];
       const isUsinagemSector = userProfile.sector?.toLowerCase() === 'usinagem';
       const hasTag = Array.isArray(tags) && tags.some((t: string) => t.toLowerCase() === 'usinagem');

       if (!isUsinagemSector || !hasTag) {
         return res.status(403).json({ error: 'Sem permissão para ajustar este item.' });
       }
    }

    const oldStock = await pool.query('SELECT quantity_on_hand, product_id FROM stock WHERE id = $1', [id]);
    await pool.query('UPDATE stock SET quantity_on_hand = $1 WHERE id = $2', [quantity_on_hand, id]);
    
    if (oldStock.rows.length > 0) {
       await createLog(userId, 'UPDATE_STOCK', { 
         stock_id: id, 
         product_id: oldStock.rows[0].product_id,
         old_qty: oldStock.rows[0].quantity_on_hand,
         new_qty: quantity_on_hand 
       }, req.ip || '127.0.0.1');
    }

    res.json({ success: true });
  } catch (error: any) {
    console.error("Erro update stock:", error);
    res.status(500).json({ error: 'Erro ao ajustar estoque' });
  }
});

app.post('/manual-entry', authenticate, async (req, res) => {
  const { items } = req.body;
  const client = await pool.connect();
  try {
    if (!items || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "Sem itens." });

    await client.query('BEGIN');
    const logRes = await client.query("INSERT INTO xml_logs (file_name, success, total_items) VALUES ($1, $2, $3) RETURNING id", [`Entrada Manual - ${new Date().toLocaleDateString('pt-BR')}`, true, items.length]);
    const logId = logRes.rows[0].id;
    
    for (const item of items) {
      if (!item.product_id || !item.quantity) throw new Error("Item inválido.");
      await client.query("INSERT INTO xml_items (xml_log_id, product_id, quantity) VALUES ($1, $2, $3)", [logId, item.product_id, item.quantity]);
      await client.query("UPDATE stock SET quantity_on_hand = COALESCE(quantity_on_hand, 0) + $1 WHERE product_id = $2", [item.quantity, item.product_id]);
    }
    await client.query('COMMIT');
    
    if ((req as any).io) {
        (req as any).io.to('compras').emit('new_request_notification', {
            message: '📦 Nova entrada de mercadoria registrada!',
            action: 'Ver Estoque'
        });
    }

    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message || "Erro na entrada" });
  } finally {
    client.release();
  }
});

app.post('/manual-withdrawal', authenticate, async (req, res) => {
  const { sector, items } = req.body;
  const client = await pool.connect();
  try {
    if (!items || !Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "Sem itens." });

    await client.query('BEGIN');
    // Note: 'manual' withdrawals still go to separations for logging, but as type='manual' and status='concluida'
    const sepRes = await client.query('INSERT INTO separations (destination, status, type) VALUES ($1, $2, $3) RETURNING id', [sector, 'concluida', 'manual']);
    const separationId = sepRes.rows[0].id;
    
    for (const item of items) {
      if (!item.product_id || !item.quantity) throw new Error("Item inválido.");
      await client.query('INSERT INTO separation_items (separation_id, product_id, quantity) VALUES ($1, $2, $3)', [separationId, item.product_id, item.quantity]);
      // Baixa direta do estoque disponível
      await client.query('UPDATE stock SET quantity_on_hand = COALESCE(quantity_on_hand, 0) - $1 WHERE product_id = $2', [item.quantity, item.product_id]);
    }
    await client.query('COMMIT');
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: error.message || "Erro na saída" });
  } finally {
    client.release();
  }
});

// --- REQUESTS ---

app.get('/requests', authenticate, async (req, res) => {
  try {
    const query = `
      SELECT r.*, json_build_object('name', p.name, 'sector', p.sector) as requester,
      (SELECT json_agg(json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'custom_product_name', ri.custom_product_name, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit) ELSE NULL END))
        FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id WHERE ri.request_id = r.id) as request_items
      FROM requests r LEFT JOIN profiles p ON r.requester_id = p.id ORDER BY r.created_at DESC
    `;
    const { rows } = await pool.query(query);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar solicitações' });
  }
});

app.get('/my-requests', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  try {
    const query = `
      SELECT r.*, (SELECT json_agg(json_build_object('id', ri.id, 'quantity_requested', ri.quantity_requested, 'custom_product_name', ri.custom_product_name, 'products', CASE WHEN pr.id IS NOT NULL THEN json_build_object('name', pr.name, 'sku', pr.sku, 'unit', pr.unit) ELSE NULL END))
        FROM request_items ri LEFT JOIN products pr ON ri.product_id = pr.id WHERE ri.request_id = r.id) as request_items
      FROM requests r WHERE r.requester_id = $1 ORDER BY r.created_at DESC
    `;
    const { rows } = await pool.query(query, [userId]);
    res.json(rows);
  } catch (error: any) {
    res.status(500).json({ error: 'Erro ao buscar minhas solicitações' });
  }
});

app.post('/requests', authenticate, async (req, res) => {
  const userId = (req as any).user.id;
  const { sector, items } = req.body;
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const reqRes = await client.query(
      'INSERT INTO requests (requester_id, sector, status) VALUES ($1, $2, $3) RETURNING id', 
      [userId, sector, 'aberto']
    );
    const requestId = reqRes.rows[0].id;

    for (const item of items) {
      const isCustom = item.product_id === 'custom' || !item.product_id;
      const productId = isCustom ? null : item.product_id;
      const customName = isCustom ? item.custom_name : null;
      
      await client.query('INSERT INTO request_items (request_id, product_id, custom_product_name, quantity_requested) VALUES ($1, $2, $3, $4)', [requestId, productId, customName, item.quantity]);
    }
    
    await client.query('COMMIT');

    // 1. Notifica via Socket (Tempo real se estiver aberto)
    if ((req as any).io) {
        (req as any).io.to('almoxarife').emit('new_request_notification', {
            message: `📢 Nova solicitação do setor: ${sector}`,
            action: 'Ver Pedidos',
            type: 'solicitacao'
        });
    }

    // 2. Notifica via PUSH
    sendPushNotificationToRole(
      'almoxarife', 
      'Nova Solicitação!', 
      `O setor ${sector} fez um novo pedido.`
    );
    
    res.status(201).json({ success: true });
  } catch (error: any) {
    await client.query('ROLLBACK');
    res.status(500).json({ error: `Erro Técnico: ${error.message}` }); 
  } finally {
    client.release();
  }
});

app.put('/requests/:id/status', authenticate, async (req, res) => {
  const { id } = req.params;
  const { status, rejection_reason } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const currentRes = await client.query('SELECT status FROM requests WHERE id = $1', [id]);
    const currentStatus = currentRes.rows[0]?.status;

    if (!currentStatus) throw new Error("Solicitação não encontrada");

    const itemsRes = await client.query('SELECT product_id, quantity_requested FROM request_items WHERE request_id = $1', [id]);
    const items = itemsRes.rows;

    if (status === 'aprovado' && currentStatus === 'aberto') {
      for (const item of items) {
        if (item.product_id) {
          const stockCheck = await client.query('SELECT quantity_on_hand FROM stock WHERE product_id = $1', [item.product_id]);
          const onHand = parseFloat(stockCheck.rows[0]?.quantity_on_hand || 0);
          
          if (onHand < item.quantity_requested) {
             throw new Error(`Estoque insuficiente para o produto ID: ${item.product_id}`);
          }

          await client.query(`
            UPDATE stock 
            SET quantity_on_hand = COALESCE(quantity_on_hand, 0) - $1,
                quantity_reserved = COALESCE(quantity_reserved, 0) + $1
            WHERE product_id = $2
          `, [item.quantity_requested, item.product_id]);
        }
      }
    }
    else if (status === 'entregue' && currentStatus === 'aprovado') {
      for (const item of items) {
        if (item.product_id) {
          await client.query(`
            UPDATE stock 
            SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1)
            WHERE product_id = $2
          `, [item.quantity_requested, item.product_id]);
        }
      }
    }
    else if (status === 'entregue' && currentStatus === 'aberto') {
      for (const item of items) {
        if (item.product_id) {
           await client.query(`
             UPDATE stock 
             SET quantity_on_hand = GREATEST(0, COALESCE(quantity_on_hand, 0) - $1)
             WHERE product_id = $2
           `, [item.quantity_requested, item.product_id]);
        }
      }
    }
    else if (status === 'rejeitado' && currentStatus === 'aprovado') {
      for (const item of items) {
        if (item.product_id) {
          await client.query(`
            UPDATE stock 
            SET quantity_on_hand = COALESCE(quantity_on_hand, 0) + $1,
                quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1)
            WHERE product_id = $2
          `, [item.quantity_requested, item.product_id]);
        }
      }
    }

    await client.query('UPDATE requests SET status = $1, rejection_reason = $2 WHERE id = $3', [status, rejection_reason || null, id]);
    
    await client.query('COMMIT');
    res.json({ success: true });

  } catch (error: any) {
    await client.query('ROLLBACK');
    const statusCode = error.message.includes('Estoque insuficiente') ? 400 : 500;
    res.status(statusCode).json({ error: error.message || 'Erro ao atualizar status' });
  } finally {
    client.release();
  }
});

app.delete('/requests/:id', authenticate, async (req, res) => {
  const { id } = req.params;
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');

    const reqRes = await client.query('SELECT status FROM requests WHERE id = $1', [id]);
    
    if (reqRes.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Solicitação não encontrada.' });
    }

    const { status } = reqRes.rows[0];

    if (status === 'aprovado') {
       const itemsRes = await client.query('SELECT product_id, quantity_requested FROM request_items WHERE request_id = $1', [id]);
       const items = itemsRes.rows;

       for (const item of items) {
         if (item.product_id) {
           await client.query(`
             UPDATE stock 
             SET quantity_reserved = GREATEST(0, COALESCE(quantity_reserved, 0) - $1),
                 quantity_on_hand = COALESCE(quantity_on_hand, 0) + $1
             WHERE product_id = $2
           `, [item.quantity_requested, item.product_id]);
         }
       }
    }

    await client.query('DELETE FROM request_items WHERE request_id = $1', [id]);
    await client.query('DELETE FROM requests WHERE id = $1', [id]);

    await client.query('COMMIT');
    res.json({ success: true });

  } catch (error: any) {
    await client.query('ROLLBACK');
    console.error("Erro ao excluir solicitação:", error);
    res.status(500).json({ error: 'Erro ao excluir solicitação' });
  } finally {
    client.release();
  }
});

// --- DASHBOARD E RELATÓRIOS ---
app.get('/reports/managerial', authenticate, async (req, res) => {
  try {
    const topProductsQuery = `
      SELECT p.name, SUM(si.quantity) as total
      FROM separation_items si
      JOIN products p ON si.product_id = p.id
      JOIN separations s ON si.separation_id = s.id
      WHERE s.status = 'concluida'
      GROUP BY p.name
      ORDER BY total DESC
      LIMIT 5
    `;
    
    const historyQuery = `
      WITH months AS (
        SELECT generate_series(
          date_trunc('month', CURRENT_DATE) - INTERVAL '5 months',
          date_trunc('month', CURRENT_DATE),
          '1 month'::interval
        ) as month
      )
      SELECT 
        TO_CHAR(m.month, 'Mon') as name,
        COALESCE(SUM(xi.quantity), 0) as entradas,
        (
          SELECT COALESCE(SUM(si.quantity), 0)
          FROM separation_items si
          JOIN separations s ON si.separation_id = s.id
          WHERE date_trunc('month', s.created_at) = m.month AND s.status = 'concluida'
        ) as saidas
      FROM months m
      LEFT JOIN xml_logs xl ON date_trunc('month', xl.created_at) = m.month
      LEFT JOIN xml_items xi ON xi.xml_log_id = xl.id
      GROUP BY m.month
      ORDER BY m.month ASC
    `;

    const statusPieQuery = `
      SELECT 
        COALESCE(purchase_status, 'pendente') as name, 
        COUNT(*) as value 
      FROM products 
      WHERE active = true 
      GROUP BY purchase_status
    `;

    const topProducts = await pool.query(topProductsQuery);
    const history = await pool.query(historyQuery);
    const statusPie = await pool.query(statusPieQuery);

    res.json({
      topProducts: topProducts.rows,
      history: history.rows,
      purchaseStatus: statusPie.rows
    });

  } catch (error: any) {
    console.error(error);
    res.status(500).json({ error: 'Erro ao gerar dados gerenciais' });
  }
});

app.get('/dashboard/stats', authenticate, async (req, res) => {
  try {
    const productsRes = await pool.query('SELECT COUNT(*) FROM products WHERE active = true');
    const lowStockRes = await pool.query(`SELECT COUNT(*) FROM products p LEFT JOIN stock s ON p.id = s.product_id WHERE p.min_stock IS NOT NULL AND (COALESCE(s.quantity_on_hand, 0) - COALESCE(s.quantity_reserved, 0)) < p.min_stock AND p.active = true`);
    const requestsRes = await pool.query('SELECT COUNT(*) FROM requests');
    const openRequestsRes = await pool.query("SELECT COUNT(*) FROM requests WHERE status = 'aberto'");
    const separationsRes = await pool.query("SELECT COUNT(*) FROM separations WHERE type = 'op' OR type = 'default'");
    
    const stockItemsRes = await pool.query(`SELECT s.quantity_on_hand, p.unit_price FROM stock s JOIN products p ON s.product_id = p.id WHERE p.active = true`);
    let totalValueCalculated = 0;
    stockItemsRes.rows.forEach((item: any) => {
        const qtd = parseFloat(item.quantity_on_hand);
        const preco = parseFloat(item.unit_price);
        if (!isNaN(qtd) && !isNaN(preco)) totalValueCalculated += qtd * preco;
    });

    res.json({
      totalProducts: parseInt(productsRes.rows[0].count),
      lowStock: parseInt(lowStockRes.rows[0].count),
      totalRequests: parseInt(requestsRes.rows[0].count),
      openRequests: parseInt(openRequestsRes.rows[0].count),
      totalSeparations: parseInt(separationsRes.rows[0].count),
      totalValue: totalValueCalculated,
    });
  } catch (error: any) { 
    res.status(500).json({ error: 'Erro stats' }); 
  }
});

app.get('/reports/available-dates', authenticate, async (req, res) => {
  try {
    const result = await pool.query(`SELECT MIN(data) as min_date, MAX(data) as max_date FROM (SELECT created_at as data FROM xml_items UNION ALL SELECT created_at as data FROM separations WHERE status = 'concluida' UNION ALL SELECT created_at as data FROM requests WHERE status IN ('aprovado', 'entregue')) as all_dates`);
    res.json(result.rows[0]);
  } catch (error: any) { res.status(500).json({ error: 'Erro dates' }); }
});

app.get('/reports/general', authenticate, async (req, res) => {
  const { startDate, endDate } = req.query;
  if (!startDate || !endDate) return res.status(400).json({ error: 'Datas obrigatórias' });
  const start = `${startDate} 00:00:00`;
  const end = `${endDate} 23:59:59`;
  try {
    const entradasRes = await pool.query(`SELECT xi.created_at as data, 'Entrada' as tipo, xl.file_name as origem, p.name as produto, p.sku, p.unit as unidade, xi.quantity as quantidade FROM xml_items xi JOIN products p ON xi.product_id = p.id JOIN xml_logs xl ON xi.xml_log_id = xl.id WHERE xi.created_at >= $1 AND xi.created_at <= $2 ORDER BY xi.created_at DESC`, [start, end]);
    const separacoesRes = await pool.query(`SELECT s.created_at as data, CASE WHEN s.type='manual' THEN 'Saída - Manual' ELSE 'Saída - Separação' END as tipo, s.destination as destino_setor, p.name as produto, p.sku, p.unit as unidade, si.quantity as quantidade FROM separation_items si JOIN separations s ON si.separation_id = s.id JOIN products p ON si.product_id = p.id WHERE s.created_at >= $1 AND s.created_at <= $2 AND s.status = 'concluida' ORDER BY s.created_at DESC`, [start, end]);
    const solicitacoesRes = await pool.query(`SELECT r.created_at as data, 'Saída - Solicitação' as tipo, COALESCE(pf.sector, r.sector) as destino_setor, pf.name as solicitante, COALESCE(p.name, ri.custom_product_name) as produto, p.sku, p.unit as unidade, ri.quantity_requested as quantidade, r.status FROM request_items ri JOIN requests r ON ri.request_id = r.id LEFT JOIN products p ON ri.product_id = p.id LEFT JOIN profiles pf ON r.requester_id = pf.id WHERE r.created_at >= $1 AND r.created_at <= $2 AND r.status IN ('aprovado', 'entregue') ORDER BY r.created_at DESC`, [start, end]);
    res.json({ entradas: entradasRes.rows, saidas_separacoes: separacoesRes.rows, saidas_solicitacoes: solicitacoesRes.rows });
  } catch (error: any) { res.status(500).json({ error: 'Erro relatório' }); }
});

app.post('/stock/calculate-min', authenticate, async (req, res) => {
  const { days } = req.body;
  const period = Number(days);
  
  if (!period || period < 7 || period > 365) {
    return res.status(400).json({ error: 'Período inválido (entre 7 e 365 dias)' });
  }

  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - period);

    const { rows: consumptionData } = await client.query(`
      SELECT 
        si.product_id, 
        p.sku,
        p.name,
        COALESCE(p.min_stock, 0) as old_min, 
        SUM(si.quantity) as total_consumed 
      FROM separation_items si 
      JOIN separations s ON si.separation_id = s.id 
      JOIN products p ON si.product_id = p.id 
      WHERE 
        s.status = 'concluida' 
        AND s.created_at >= $1
        AND p.active = true
        AND p.name NOT ILIKE '%teste%'  
        AND p.name NOT ILIKE '%exemplo%' 
        AND p.sku NOT ILIKE 'TESTE%'    
      GROUP BY si.product_id, p.sku, p.name, p.min_stock
    `, [cutoffDate]);

    let updatedProducts: any[] = []; 

    for (const item of consumptionData) {
      const total = parseFloat(item.total_consumed);
      const avgDaily = total / period;
      
      const newMinStock = Math.ceil(avgDaily * 15);

      if (newMinStock > 0 && newMinStock !== parseFloat(item.old_min)) {
        await client.query('UPDATE products SET min_stock = $1 WHERE id = $2', [newMinStock, item.product_id]);
        
        updatedProducts.push({
          id: item.product_id,
          sku: item.sku,
          name: item.name,
          oldMin: parseFloat(item.old_min),
          newMin: newMinStock,
          avgConsumption: parseFloat(avgDaily.toFixed(2))
        });
      }
    }

    await client.query('COMMIT');
    
    res.json({ 
      success: true, 
      message: `Cálculo concluído. ${updatedProducts.length} produtos alterados.`,
      updatedProducts: updatedProducts 
    });
    
  } catch (error: any) {
    await client.query('ROLLBACK');
    console.error("Erro no cálculo de mínimo:", error);
    res.status(500).json({ error: error.message });
  } finally { 
    client.release(); 
  }
});

app.post('/admin/reset-password', authenticate, async (req, res) => {
  const { userId, newPassword } = req.body;
  const requesterId = (req as any).user.id;
  const adminCheck = await pool.query("SELECT role FROM profiles WHERE id = $1", [requesterId]);
  if (adminCheck.rows[0]?.role !== 'admin') return res.status(403).json({ error: 'Apenas admins.' });
  try {
    const salt = await bcrypt.genSalt(10);
    const encryptedPassword = await bcrypt.hash(newPassword, salt);
    await pool.query('UPDATE users SET encrypted_password = $1 WHERE id = $2', [encryptedPassword, userId]);
    
    await createLog(requesterId, 'RESET_PASSWORD', { target_user_id: userId }, req.ip || '127.0.0.1');

    res.json({ success: true, message: 'Senha redefinida.' });
  } catch (error: any) { res.status(500).json({ error: 'Erro reset' }); }
});

const PORT = process.env.PORT || 3000;
httpServer.listen(PORT, () => console.log(`🚀 Fluxo Royale 2.1 Online na porta ${PORT}`));
