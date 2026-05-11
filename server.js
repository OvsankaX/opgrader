const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// ✅ СЕКРЕТ ТОЛЬКО ИЗ ПЕРЕМЕННОЙ ОКРУЖЕНИЯ (Render)
const SECRET_KEY = process.env.SECRET_KEY;
if (!SECRET_KEY) {
    console.error('❌ SECRET_KEY not set! Add it in Render Environment Variables');
    process.exit(1);
}

// ✅ ПОДКЛЮЧЕНИЕ К POSTGRESQL (Neon / Supabase)
const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
    console.error('❌ DATABASE_URL not set! Add it in Render Environment Variables');
    process.exit(1);
}

const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// ✅ ЗАЩИТА ОТ БРУТФОРСА И СПАМА
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    message: { error: 'TOO_MANY_REQUESTS', message: 'Слишком много запросов, подождите' }
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    skipSuccessfulRequests: true,
    message: { error: 'TOO_MANY_ATTEMPTS', message: 'Слишком много попыток, подождите 15 минут' }
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));
app.use('/api/', globalLimiter);
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);

// ✅ ЗАЩИТА ОТ МАССОВОЙ РЕГИСТРАЦИИ (по IP)
const registerAttempts = new Map();
setInterval(() => {
    const now = Date.now();
    for (const [ip, data] of registerAttempts.entries()) {
        if (now - data.timestamp > 3600000) {
            registerAttempts.delete(ip);
        }
    }
}, 3600000);

// ✅ СОЗДАНИЕ ТАБЛИЦ В POSTGRESQL
async function initDB() {
    try {
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                balance INTEGER DEFAULT 1000,
                best_item TEXT DEFAULT '',
                best_chance INTEGER DEFAULT 0,
                best_price INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS inventory (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                item_name TEXT,
                item_price INTEGER,
                is_upgraded INTEGER DEFAULT 0,
                upgraded_at TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS stats (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                ups INTEGER DEFAULT 0,
                earned INTEGER DEFAULT 0,
                lost INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS items_pool (
                id SERIAL PRIMARY KEY,
                item_name TEXT UNIQUE,
                is_active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS clicker_stats (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                last_click_time BIGINT DEFAULT 0,
                clicked_today INTEGER DEFAULT 0,
                total_clicks INTEGER DEFAULT 0
            );
        `);
        console.log('✅ Tables created');

        // Наполняем пул предметов
        const defaultItems = [
            'СПИД', 'Ваня Зойцев', 'Дима Баранав', 'Яйца',
            'Кейс-Батл', 'ZOV', 'Зюзя', 'Satella666', 'Донк', 'Гавно'
        ];
        
        for (const item of defaultItems) {
            await pool.query(`INSERT INTO items_pool (item_name) VALUES ($1) ON CONFLICT (item_name) DO NOTHING`, [item]);
        }
        console.log('✅ Items pool populated');
    } catch (err) {
        console.error('❌ DB Init Error:', err);
    }
}

initDB();

// Middleware
const authMiddleware = async (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token' });
    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        req.userId = decoded.userId;
        next();
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

// ========== АВТОРИЗАЦИЯ ==========

app.post('/api/register', async (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;
    
    const attempts = registerAttempts.get(clientIp);
    if (attempts && attempts.count >= 3) {
        return res.status(429).json({ 
            error: 'TOO_MANY_ACCOUNTS', 
            message: 'С одного IP можно зарегистрировать не более 3 аккаунтов в час' 
        });
    }
    
    if (username.length > 16) return res.status(400).json({ error: 'USERNAME_TOO_LONG' });
    if (password.length > 32) return res.status(400).json({ error: 'PASSWORD_TOO_LONG' });
    if (username.length < 3) return res.status(400).json({ error: 'USERNAME_TOO_SHORT' });
    if (password.length < 3) return res.status(400).json({ error: 'PASSWORD_TOO_SHORT' });
    
    try {
        const existing = await pool.query(`SELECT id FROM users WHERE username = $1`, [username]);
        if (existing.rows.length > 0) return res.status(400).json({ error: 'USERNAME_TAKEN' });
        
        const hashedPassword = bcrypt.hashSync(password, 10);
        const result = await pool.query(
            `INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id`,
            [username, hashedPassword]
        );
        const userId = result.rows[0].id;
        
        await pool.query(`INSERT INTO stats (user_id, ups, earned, lost) VALUES ($1, 0, 0, 0)`, [userId]);
        await pool.query(`INSERT INTO clicker_stats (user_id, last_click_time, clicked_today, total_clicks) VALUES ($1, 0, 0, 0)`, [userId]);
        
        console.log(`📝 New user registered: ${username} from ${clientIp}`);
        
        if (attempts) {
            registerAttempts.set(clientIp, { count: attempts.count + 1, timestamp: Date.now() });
        } else {
            registerAttempts.set(clientIp, { count: 1, timestamp: Date.now() });
        }
        
        const token = jwt.sign({ userId }, SECRET_KEY);
        res.json({ token, userId, username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;
    const clientIp = req.ip || req.connection.remoteAddress;
    
    try {
        const result = await pool.query(`SELECT * FROM users WHERE username = $1`, [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'USER_NOT_FOUND' });
        
        const user = result.rows[0];
        if (!bcrypt.compareSync(password, user.password)) {
            console.log(`⚠️ Failed login attempt for ${username} from ${clientIp}`);
            return res.status(401).json({ error: 'WRONG_PASSWORD' });
        }
        
        console.log(`✅ User logged in: ${username} from ${clientIp}`);
        const token = jwt.sign({ userId: user.id }, SECRET_KEY);
        res.json({ token, userId: user.id, username: user.username });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

app.get('/api/user/:userId', authMiddleware, async (req, res) => {
    const userId = req.params.userId;
    
    try {
        const userResult = await pool.query(`SELECT * FROM users WHERE id = $1`, [userId]);
        if (userResult.rows.length === 0) return res.status(404).json({ error: 'User not found' });
        const user = userResult.rows[0];
        
        const inventory = await pool.query(`SELECT * FROM inventory WHERE user_id = $1`, [userId]);
        const stats = await pool.query(`SELECT * FROM stats WHERE user_id = $1`, [userId]);
        const clickerStats = await pool.query(`SELECT * FROM clicker_stats WHERE user_id = $1`, [userId]);
        
        res.json({
            id: user.id,
            username: user.username,
            balance: user.balance,
            best_item: user.best_item || '',
            best_chance: user.best_chance || 0,
            best_price: user.best_price || 0,
            inventory: inventory.rows || [],
            stats: stats.rows[0] || { ups: 0, earned: 0, lost: 0 },
            clickerStats: clickerStats.rows[0] || { last_click_time: 0, clicked_today: 0, total_clicks: 0 }
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

// ========== КЛИКЕР ==========

app.get('/api/clicker/stats', authMiddleware, async (req, res) => {
    const userId = req.userId;
    
    try {
        let stats = await pool.query(`SELECT * FROM clicker_stats WHERE user_id = $1`, [userId]);
        
        if (stats.rows.length === 0) {
            await pool.query(`INSERT INTO clicker_stats (user_id) VALUES ($1)`, [userId]);
            return res.json({ canClick: true, remaining: 5000, lastClickTime: 0, clickedToday: 0, totalClicks: 0 });
        }
        
        const now = Date.now();
        const hour = 3600000;
        let clickedToday = stats.rows[0].clicked_today;
        
        if (now - stats.rows[0].last_click_time >= hour && clickedToday > 0) {
            clickedToday = 0;
            await pool.query(`UPDATE clicker_stats SET clicked_today = 0, last_click_time = $1 WHERE user_id = $2`, [now, userId]);
        }
        
        const remaining = Math.max(0, 5000 - clickedToday);
        res.json({
            canClick: remaining > 0,
            remaining: remaining,
            lastClickTime: stats.rows[0].last_click_time,
            clickedToday: clickedToday,
            totalClicks: stats.rows[0].total_clicks
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

app.post('/api/clicker/click', authMiddleware, async (req, res) => {
    const userId = req.userId;
    const CLICK_REWARD = 10;
    const MAX_PER_HOUR = 5000;
    
    try {
        let stats = await pool.query(`SELECT * FROM clicker_stats WHERE user_id = $1`, [userId]);
        
        if (stats.rows.length === 0) {
            await pool.query(`INSERT INTO clicker_stats (user_id, last_click_time, clicked_today, total_clicks) VALUES ($1, $2, 10, 10)`, [userId, Date.now()]);
            await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [CLICK_REWARD, userId]);
            const user = await pool.query(`SELECT balance FROM users WHERE id = $1`, [userId]);
            return res.json({ success: true, earned: CLICK_REWARD, newBalance: user.rows[0].balance, remaining: MAX_PER_HOUR - CLICK_REWARD, clickedToday: CLICK_REWARD, totalClicks: CLICK_REWARD });
        }
        
        const now = Date.now();
        const hour = 3600000;
        let clickedToday = stats.rows[0].clicked_today;
        
        if (now - stats.rows[0].last_click_time >= hour) {
            clickedToday = 0;
        }
        
        if (clickedToday + CLICK_REWARD > MAX_PER_HOUR) {
            const waitTime = Math.ceil((hour - (now - stats.rows[0].last_click_time)) / 60000);
            return res.status(429).json({ error: 'LIMIT_REACHED', message: `Лимит ${MAX_PER_HOUR} в час. Подождите ${waitTime} минут`, waitMinutes: waitTime });
        }
        
        const newClickedToday = clickedToday + CLICK_REWARD;
        const newTotalClicks = (stats.rows[0].total_clicks || 0) + CLICK_REWARD;
        
        await pool.query(`UPDATE clicker_stats SET last_click_time = $1, clicked_today = $2, total_clicks = $3 WHERE user_id = $4`, [now, newClickedToday, newTotalClicks, userId]);
        await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [CLICK_REWARD, userId]);
        
        const user = await pool.query(`SELECT balance FROM users WHERE id = $1`, [userId]);
        
        res.json({ success: true, earned: CLICK_REWARD, newBalance: user.rows[0].balance, remaining: MAX_PER_HOUR - newClickedToday, clickedToday: newClickedToday, totalClicks: newTotalClicks });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

// ========== РУЛЕТКА ==========

app.post('/api/spin', authMiddleware, async (req, res) => {
    const { userId, itemId, chance } = req.body;
    
    try {
        const item = await pool.query(`SELECT * FROM inventory WHERE id = $1 AND user_id = $2`, [itemId, userId]);
        if (item.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        
        const win = Math.random() * 100 < chance;
        const spinDuration = 2000 + Math.random() * 1500;
        
        const winSize = (chance / 100) * 360;
        let targetDeg;
        
        if (win) {
            const zoneStart = 180 - winSize / 2;
            const zoneEnd = 180 + winSize / 2;
            targetDeg = zoneStart + Math.random() * winSize;
        } else {
            const zoneStart = 180 - winSize / 2;
            const zoneEnd = 180 + winSize / 2;
            if (Math.random() < 0.5) {
                targetDeg = Math.random() * (zoneStart);
            } else {
                targetDeg = zoneEnd + Math.random() * (360 - zoneEnd);
            }
        }
        
        targetDeg = targetDeg % 360;
        
        let result = { win, targetDeg, itemName: item.rows[0].item_name, spinDuration };
        
        if (win) {
            const profit = Math.floor(item.rows[0].item_price * (100 / chance)) - item.rows[0].item_price;
            const newPrice = item.rows[0].item_price + profit;
            result.newPrice = newPrice;
            result.profit = profit;
            
            await pool.query(`UPDATE inventory SET item_price = $1, is_upgraded = 1, upgraded_at = NOW() WHERE id = $2`, [newPrice, itemId]);
            await pool.query(`UPDATE stats SET ups = ups + 1, earned = earned + $1 WHERE user_id = $2`, [profit, userId]);
            
            const user = await pool.query(`SELECT best_price FROM users WHERE id = $1`, [userId]);
            if (newPrice > (user.rows[0]?.best_price || 0)) {
                await pool.query(`UPDATE users SET best_item = $1, best_price = $2, best_chance = $3 WHERE id = $4`, [item.rows[0].item_name, newPrice, chance, userId]);
            }
        } else {
            await pool.query(`DELETE FROM inventory WHERE id = $1`, [itemId]);
            await pool.query(`UPDATE stats SET lost = lost + $1 WHERE user_id = $2`, [item.rows[0].item_price, userId]);
            result.lossAmount = item.rows[0].item_price;
        }
        
        res.json(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

app.get('/api/items-pool', authMiddleware, async (req, res) => {
    const items = await pool.query(`SELECT item_name FROM items_pool WHERE is_active = 1`);
    res.json(items.rows.map(i => i.item_name));
});

// ========== МАГАЗИН ==========

app.post('/api/buy-item', authMiddleware, async (req, res) => {
    const { userId, itemName, itemPrice } = req.body;
    
    try {
        const user = await pool.query(`SELECT balance FROM users WHERE id = $1`, [userId]);
        if (!user.rows[0] || user.rows[0].balance < itemPrice) {
            return res.status(400).json({ error: 'Insufficient balance' });
        }
        
        await pool.query(`UPDATE users SET balance = balance - $1 WHERE id = $2`, [itemPrice, userId]);
        await pool.query(`INSERT INTO inventory (user_id, item_name, item_price, is_upgraded) VALUES ($1, $2, $3, 0)`, [userId, itemName, itemPrice]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

app.post('/api/sell-item', authMiddleware, async (req, res) => {
    const { userId, itemId, itemPrice } = req.body;
    
    try {
        await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [itemPrice, userId]);
        await pool.query(`DELETE FROM inventory WHERE id = $1 AND user_id = $2`, [itemId, userId]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

app.post('/api/sell-all', authMiddleware, async (req, res) => {
    const { userId, totalPrice } = req.body;
    
    try {
        await pool.query(`UPDATE users SET balance = balance + $1 WHERE id = $2`, [totalPrice, userId]);
        await pool.query(`DELETE FROM inventory WHERE user_id = $1`, [userId]);
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'DB_ERROR' });
    }
});

// ========== ЛИДЕРБОРД ==========

app.get('/api/leaderboard/:type', async (req, res) => {
    const type = req.params.type;
    let query = '';
    if (type === 'wins') {
        query = `SELECT u.username, s.earned as total FROM stats s JOIN users u ON u.id = s.user_id ORDER BY s.earned DESC LIMIT 50`;
    } else if (type === 'losses') {
        query = `SELECT u.username, s.lost as total FROM stats s JOIN users u ON u.id = s.user_id ORDER BY s.lost DESC LIMIT 50`;
    } else {
        query = `SELECT u.username, (s.earned - s.lost) as total FROM stats s JOIN users u ON u.id = s.user_id ORDER BY total DESC LIMIT 50`;
    }
    const rows = await pool.query(query);
    res.json(rows.rows || []);
});

app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`🔐 Security: Rate limiting + PostgreSQL enabled`);
});
