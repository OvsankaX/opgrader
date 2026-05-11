const express = require('express');
const Database = require('better-sqlite3');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || 'sg8ASkogf28hnHFbf_s23faS';

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Подключение к БД (синхронное)
const db = new Database('./OPGRADOR.db');
console.log('✅ Database connected');

// Создание таблиц (синхронно)
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        balance INTEGER DEFAULT 1000,
        best_item TEXT DEFAULT '',
        best_chance INTEGER DEFAULT 0,
        best_price INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS inventory (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        item_name TEXT,
        item_price INTEGER,
        is_upgraded INTEGER DEFAULT 0,
        upgraded_at DATETIME,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS stats (
        user_id INTEGER PRIMARY KEY,
        ups INTEGER DEFAULT 0,
        earned INTEGER DEFAULT 0,
        lost INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS items_pool (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        item_name TEXT UNIQUE,
        is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS clicker_stats (
        user_id INTEGER PRIMARY KEY,
        last_click_time INTEGER DEFAULT 0,
        clicked_today INTEGER DEFAULT 0,
        total_clicks INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
`);

// Добавляем недостающие колонки (если их нет)
try {
    db.exec(`ALTER TABLE inventory ADD COLUMN is_upgraded INTEGER DEFAULT 0`);
} catch(e) {}
try {
    db.exec(`ALTER TABLE inventory ADD COLUMN upgraded_at DATETIME`);
} catch(e) {}
try {
    db.exec(`ALTER TABLE users ADD COLUMN best_item TEXT DEFAULT ''`);
} catch(e) {}
try {
    db.exec(`ALTER TABLE users ADD COLUMN best_chance INTEGER DEFAULT 0`);
} catch(e) {}
try {
    db.exec(`ALTER TABLE users ADD COLUMN best_price INTEGER DEFAULT 0`);
} catch(e) {}

// Наполняем пул предметов
const defaultItems = [
    'СПИД', 'Ваня Зойцев', 'Дима Баранав', 'Яйца',
    'Кейс-Батл', 'ZOV', 'Зюзя', 'Satella666', 'Донк', 'Гавно'
];

const insertItem = db.prepare(`INSERT OR IGNORE INTO items_pool (item_name) VALUES (?)`);
defaultItems.forEach(item => {
    insertItem.run(item);
});

// Middleware для проверки токена
const authMiddleware = (req, res, next) => {
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

// Регистрация
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    
    if (username.length > 16) return res.status(400).json({ error: 'USERNAME_TOO_LONG' });
    if (password.length > 32) return res.status(400).json({ error: 'PASSWORD_TOO_LONG' });
    
    const user = db.prepare(`SELECT id FROM users WHERE username = ?`).get(username);
    if (user) return res.status(400).json({ error: 'USERNAME_TAKEN' });
    
    const hashedPassword = bcrypt.hashSync(password, 10);
    const result = db.prepare(`INSERT INTO users (username, password) VALUES (?, ?)`).run(username, hashedPassword);
    const userId = result.lastInsertRowid;
    
    db.prepare(`INSERT INTO stats (user_id) VALUES (?)`).run(userId);
    db.prepare(`INSERT INTO clicker_stats (user_id, last_click_time, clicked_today, total_clicks) VALUES (?, 0, 0, 0)`).run(userId);
    
    const token = jwt.sign({ userId }, SECRET_KEY);
    res.json({ token, userId, username });
});

// Логин
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    const user = db.prepare(`SELECT * FROM users WHERE username = ?`).get(username);
    if (!user) return res.status(401).json({ error: 'USER_NOT_FOUND' });
    if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'WRONG_PASSWORD' });
    
    const token = jwt.sign({ userId: user.id }, SECRET_KEY);
    res.json({ token, userId: user.id, username: user.username });
});

// Получение данных пользователя
app.get('/api/user/:userId', authMiddleware, (req, res) => {
    const userId = req.params.userId;
    
    const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(userId);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const inventory = db.prepare(`SELECT * FROM inventory WHERE user_id = ?`).all(userId);
    const stats = db.prepare(`SELECT * FROM stats WHERE user_id = ?`).get(userId);
    const clickerStats = db.prepare(`SELECT * FROM clicker_stats WHERE user_id = ?`).get(userId);
    
    res.json({
        id: user.id,
        username: user.username,
        balance: user.balance,
        best_item: user.best_item || '',
        best_chance: user.best_chance || 0,
        best_price: user.best_price || 0,
        inventory: inventory || [],
        stats: stats || { ups: 0, earned: 0, lost: 0 },
        clickerStats: clickerStats || { last_click_time: 0, clicked_today: 0, total_clicks: 0 }
    });
});

// ========== КЛИКЕР ==========

// Получить статистику кликера
app.get('/api/clicker/stats', authMiddleware, (req, res) => {
    const userId = req.userId;
    
    let stats = db.prepare(`SELECT last_click_time, clicked_today, total_clicks FROM clicker_stats WHERE user_id = ?`).get(userId);
    
    if (!stats) {
        db.prepare(`INSERT INTO clicker_stats (user_id, last_click_time, clicked_today, total_clicks) VALUES (?, 0, 0, 0)`).run(userId);
        return res.json({ canClick: true, remaining: 5000, lastClickTime: 0, clickedToday: 0, totalClicks: 0 });
    }
    
    const now = Date.now();
    const hour = 3600000;
    const timeSinceLastClick = now - stats.last_click_time;
    
    let clickedToday = stats.clicked_today;
    if (timeSinceLastClick >= hour && clickedToday > 0) {
        clickedToday = 0;
        db.prepare(`UPDATE clicker_stats SET clicked_today = 0, last_click_time = ? WHERE user_id = ?`).run(now, userId);
    }
    
    const remaining = Math.max(0, 5000 - clickedToday);
    
    res.json({
        canClick: remaining > 0,
        remaining: remaining,
        lastClickTime: stats.last_click_time,
        clickedToday: clickedToday,
        totalClicks: stats.total_clicks
    });
});

// Сделать клик
app.post('/api/clicker/click', authMiddleware, (req, res) => {
    const userId = req.userId;
    const CLICK_REWARD = 10;
    const MAX_PER_HOUR = 5000;
    
    let stats = db.prepare(`SELECT last_click_time, clicked_today, total_clicks FROM clicker_stats WHERE user_id = ?`).get(userId);
    
    if (!stats) {
        db.prepare(`INSERT INTO clicker_stats (user_id, last_click_time, clicked_today, total_clicks) VALUES (?, ?, 10, 10)`).run(userId, Date.now());
        db.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`).run(CLICK_REWARD, userId);
        const user = db.prepare(`SELECT balance FROM users WHERE id = ?`).get(userId);
        return res.json({ success: true, earned: CLICK_REWARD, newBalance: user.balance, remaining: MAX_PER_HOUR - CLICK_REWARD, clickedToday: CLICK_REWARD, totalClicks: CLICK_REWARD });
    }
    
    const now = Date.now();
    const hour = 3600000;
    const timeSinceLastClick = now - stats.last_click_time;
    
    let clickedToday = stats.clicked_today;
    if (timeSinceLastClick >= hour) {
        clickedToday = 0;
    }
    
    if (clickedToday + CLICK_REWARD > MAX_PER_HOUR) {
        const waitTime = Math.ceil((hour - timeSinceLastClick) / 60000);
        return res.status(429).json({ 
            error: 'LIMIT_REACHED', 
            message: `Лимит ${MAX_PER_HOUR} гривен в час. Подождите ${waitTime} минут`,
            waitMinutes: waitTime
        });
    }
    
    const newClickedToday = clickedToday + CLICK_REWARD;
    const newTotalClicks = (stats.total_clicks || 0) + CLICK_REWARD;
    
    db.prepare(`UPDATE clicker_stats SET last_click_time = ?, clicked_today = ?, total_clicks = ? WHERE user_id = ?`).run(now, newClickedToday, newTotalClicks, userId);
    db.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`).run(CLICK_REWARD, userId);
    
    const user = db.prepare(`SELECT balance FROM users WHERE id = ?`).get(userId);
    
    res.json({ 
        success: true, 
        earned: CLICK_REWARD, 
        newBalance: user.balance,
        remaining: MAX_PER_HOUR - newClickedToday,
        clickedToday: newClickedToday,
        totalClicks: newTotalClicks
    });
});

// ========== РУЛЕТКА ==========

// Спин (рулетка)
app.post('/api/spin', authMiddleware, (req, res) => {
    const { userId, itemId, chance } = req.body;
    
    const item = db.prepare(`SELECT * FROM inventory WHERE id = ? AND user_id = ?`).get(itemId, userId);
    if (!item) return res.status(404).json({ error: 'Item not found' });
    
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
    
    let result = { win, targetDeg, itemName: item.item_name, spinDuration };
    let profit = 0;
    
    if (win) {
        profit = Math.floor(item.item_price * (100 / chance)) - item.item_price;
        const newPrice = item.item_price + profit;
        result.newPrice = newPrice;
        result.profit = profit;
        result.winAmount = profit;
        
        db.prepare(`UPDATE inventory SET item_price = ?, is_upgraded = 1, upgraded_at = datetime('now') WHERE id = ?`).run(newPrice, itemId);
        db.prepare(`UPDATE stats SET ups = ups + 1, earned = earned + ? WHERE user_id = ?`).run(profit, userId);
        
        const user = db.prepare(`SELECT best_price FROM users WHERE id = ?`).get(userId);
        if (newPrice > (user?.best_price || 0)) {
            db.prepare(`UPDATE users SET best_item = ?, best_price = ?, best_chance = ? WHERE id = ?`).run(item.item_name, newPrice, chance, userId);
        }
    } else {
        db.prepare(`DELETE FROM inventory WHERE id = ?`).run(itemId);
        db.prepare(`UPDATE stats SET lost = lost + ? WHERE user_id = ?`).run(item.item_price, userId);
        result.lossAmount = item.item_price;
    }
    
    res.json(result);
});

// Получение предметов из пула
app.get('/api/items-pool', authMiddleware, (req, res) => {
    const items = db.prepare(`SELECT item_name FROM items_pool WHERE is_active = 1`).all();
    res.json(items.map(i => i.item_name));
});

// ========== МАГАЗИН ==========

// Покупка предмета
app.post('/api/buy-item', authMiddleware, (req, res) => {
    const { userId, itemName, itemPrice } = req.body;
    
    const user = db.prepare(`SELECT balance FROM users WHERE id = ?`).get(userId);
    if (!user || user.balance < itemPrice) {
        return res.status(400).json({ error: 'Insufficient balance' });
    }
    
    db.prepare(`UPDATE users SET balance = balance - ? WHERE id = ?`).run(itemPrice, userId);
    db.prepare(`INSERT INTO inventory (user_id, item_name, item_price, is_upgraded) VALUES (?, ?, ?, 0)`).run(userId, itemName, itemPrice);
    res.json({ success: true });
});

// Продажа предмета
app.post('/api/sell-item', authMiddleware, (req, res) => {
    const { userId, itemId, itemPrice } = req.body;
    
    db.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`).run(itemPrice, userId);
    db.prepare(`DELETE FROM inventory WHERE id = ? AND user_id = ?`).run(itemId, userId);
    res.json({ success: true });
});

// Продажа всех предметов
app.post('/api/sell-all', authMiddleware, (req, res) => {
    const { userId, totalPrice } = req.body;
    
    db.prepare(`UPDATE users SET balance = balance + ? WHERE id = ?`).run(totalPrice, userId);
    db.prepare(`DELETE FROM inventory WHERE user_id = ?`).run(userId);
    res.json({ success: true });
});

// ========== ТАБЛИЦА ЛИДЕРОВ ==========

app.get('/api/leaderboard/:type', (req, res) => {
    const type = req.params.type;
    let query = '';
    if (type === 'wins') {
        query = `SELECT u.username, s.earned as total FROM stats s JOIN users u ON u.id = s.user_id ORDER BY s.earned DESC LIMIT 50`;
    } else if (type === 'losses') {
        query = `SELECT u.username, s.lost as total FROM stats s JOIN users u ON u.id = s.user_id ORDER BY s.lost DESC LIMIT 50`;
    } else {
        query = `SELECT u.username, (s.earned - s.lost) as total FROM stats s JOIN users u ON u.id = s.user_id ORDER BY total DESC LIMIT 50`;
    }
    const rows = db.prepare(query).all();
    res.json(rows || []);
});

// Запуск сервера
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
});
