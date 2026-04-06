const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const { open } = require('sqlite');
const path = require('path');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.JWT_SECRET || "ma_cle_secrete_2024";

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

let db;

// Connexion BDD et Création des tables
async function connectDB() {
    const dbPath = process.env.DATABASE_PATH || path.join(__dirname, 'blog.db');
    db = await open({ filename: dbPath, driver: sqlite3.Database });
    
    await db.exec(`
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            username TEXT UNIQUE, 
            password TEXT
        );
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT, 
            title TEXT, 
            content TEXT, 
            author TEXT, 
            date TEXT, 
            category TEXT
        );
    `);
    console.log("✅ Base de données opérationnelle");
}

// --- AUTHENTIFICATION ---

// Inscription (Email ou Numéro)
app.post('/api/auth/register', async (req, res) => {
    const { contact, password } = req.body;
    try {
        const hash = await bcrypt.hash(password, 10);
        await db.run('INSERT INTO users (username, password) VALUES (?, ?)', [contact, hash]);
        res.json({ success: true, message: "Inscription réussie" });
    } catch (err) {
        res.status(400).json({ error: "Cet email ou numéro est déjà utilisé." });
    }
});

// Connexion
app.post('/api/auth/login', async (req, res) => {
    const { contact, password } = req.body;
    const user = await db.get('SELECT * FROM users WHERE username = ?', [contact]);
    
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user.id, username: user.username }, SECRET_KEY, { expiresIn: '24h' });
        res.json({ token });
    } else {
        res.status(401).json({ error: "Identifiants incorrects" });
    }
});

// --- ARTICLES ---
app.get('/api/articles', async (req, res) => {
    const articles = await db.all('SELECT * FROM articles ORDER BY id DESC');
    res.json(articles);
});

// Servir le fichier HTML
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'index1.html'));
});

connectDB().then(() => {
    app.listen(PORT, () => console.log(`🚀 Serveur lancé sur le port ${PORT}`));
});
