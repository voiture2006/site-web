const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.JWT_SECRET || "ma_cle_secrete_pour_le_blog"; 

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname));

let db;

async function connectDB() {
    try {
        const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'blog.db');
        db = await open({
            filename: dbPath,
            driver: sqlite3.Database
        });
        
        await db.exec(`
            CREATE TABLE IF NOT EXISTS articles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                author TEXT NOT NULL,
                date TEXT NOT NULL,
                category TEXT NOT NULL,
                tags TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);

        await db.exec(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT
            )
        `);
        console.log('✅ Base de données prête');
    } catch (error) {
        console.error('❌ Erreur SQLite:', error.message);
    }
}

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: "Authentification requise" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: "Session invalide" });
        req.user = user;
        next();
    });
};

app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: "Identifiants incorrects" });
    }
});

app.get('/api/auth/setup-admin', async (req, res) => {
    try {
        const hash = await bcrypt.hash("ton_mot_de_passe", 10);
        await db.run('INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)', ["admin", hash]);
        res.json({ message: "Admin configuré" });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/articles', async (req, res) => {
    const articles = await db.all('SELECT * FROM articles ORDER BY id DESC');
    res.json(articles);
});

app.post('/api/articles', authenticateToken, async (req, res) => {
    const { title, content, author, date, category, tags } = req.body;
    const result = await db.run(
        'INSERT INTO articles (title, content, author, date, category, tags) VALUES (?,?,?,?,?,?)',
        [title, content, author, date, category, JSON.stringify(tags)]
    );
    res.json({ id: result.lastID });
});

app.delete('/api/articles/:id', authenticateToken, async (req, res) => {
    await db.run('DELETE FROM articles WHERE id = ?', [req.params.id]);
    res.json({ success: true });
});

app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index1.html'));
});

async function start() {
    await connectDB();
    app.listen(PORT, () => console.log(`Serveur démarré sur port ${PORT}`));
}
start();
