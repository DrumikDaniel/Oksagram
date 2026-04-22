// ============================================
// OKSAGRAM - ПОЛНАЯ ВЕРСИЯ
// Каналы, сообщества, школьные чаты, тематы
// Шифрование AES-256-GCM
// Обязательная регистрация + личные чаты
// ============================================

require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const multer = require('multer');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const compression = require('compression');

// ============ КОНФИГУРАЦИЯ ============
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString('hex');
const PORT = process.env.PORT || 3000;
const DATA_DIR = path.join(__dirname, 'data');
const UPLOAD_DIR = path.join(DATA_DIR, 'uploads');
const AVATAR_DIR = path.join(DATA_DIR, 'avatars');
const STICKER_DIR = path.join(DATA_DIR, 'stickers');
const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB
const MESSAGE_LIMIT = 200;
const AUDIO_RECORDING_LIMIT = 120000; // 2 минуты

// Создание директорий
[ DATA_DIR, UPLOAD_DIR, AVATAR_DIR, STICKER_DIR ].forEach(dir => {
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// ============ БАЗА ДАННЫХ (JSON файлы) ============
let users = {};           // userId -> { id, username, passwordHash, avatar, createdAt, lastSeen, theme, globalNickname, teacherAccount }
let chats = {};           // chatId -> { id, type, name, participants, messages, createdAt, encryptedKeys, avatar, description, adminCode, ownerCode, permissions, public, attachedChatId, teacher, students, currentQuiz, members, chats: {...} }
let messages = {};        // chatId -> [message]
let globalStickers = [];  // [{ id, url, addedBy, addedAt }]
let favorites = {         // userId -> { chats: [chatId], messages: [messageId], stickers: [stickerId] }
    chats: {},
    messages: {},
    stickers: {}
};
let forwardBuffer = {};   // userId -> [message]
let userSessions = {};    // token -> { userId, expiresAt }

// ============ ЗАГРУЗКА/СОХРАНЕНИЕ ДАННЫХ ============
function loadData() {
    try {
        if (fs.existsSync(path.join(DATA_DIR, 'users.json'))) users = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'users.json'), 'utf8'));
        if (fs.existsSync(path.join(DATA_DIR, 'chats.json'))) chats = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'chats.json'), 'utf8'));
        if (fs.existsSync(path.join(DATA_DIR, 'messages.json'))) messages = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'messages.json'), 'utf8'));
        if (fs.existsSync(path.join(DATA_DIR, 'globalStickers.json'))) globalStickers = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'globalStickers.json'), 'utf8'));
        if (fs.existsSync(path.join(DATA_DIR, 'favorites.json'))) favorites = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'favorites.json'), 'utf8'));
        if (fs.existsSync(path.join(DATA_DIR, 'forwardBuffer.json'))) forwardBuffer = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'forwardBuffer.json'), 'utf8'));
        if (fs.existsSync(path.join(DATA_DIR, 'sessions.json'))) userSessions = JSON.parse(fs.readFileSync(path.join(DATA_DIR, 'sessions.json'), 'utf8'));
    } catch (e) { console.error('Ошибка загрузки данных:', e); }
}

function saveData() {
    fs.writeFileSync(path.join(DATA_DIR, 'users.json'), JSON.stringify(users, null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'chats.json'), JSON.stringify(chats, null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'messages.json'), JSON.stringify(messages, null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'globalStickers.json'), JSON.stringify(globalStickers, null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'favorites.json'), JSON.stringify(favorites, null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'forwardBuffer.json'), JSON.stringify(forwardBuffer, null, 2));
    fs.writeFileSync(path.join(DATA_DIR, 'sessions.json'), JSON.stringify(userSessions, null, 2));
}

loadData();
setInterval(saveData, 60000);

// ============ КРИПТОГРАФИЯ (AES-256-GCM) ============
function generateAESKey() {
    return crypto.randomBytes(32);
}

function encryptMessage(plaintext, key, associatedData = '') {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    if (associatedData) cipher.setAAD(Buffer.from(associatedData));
    let encrypted = cipher.update(plaintext, 'utf8', 'base64');
    encrypted += cipher.final('base64');
    const authTag = cipher.getAuthTag();
    return { encrypted, iv: iv.toString('base64'), authTag: authTag.toString('base64') };
}

function decryptMessage(encryptedData, key, associatedData = '') {
    try {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encryptedData.iv, 'base64'));
        decipher.setAuthTag(Buffer.from(encryptedData.authTag, 'base64'));
        if (associatedData) decipher.setAAD(Buffer.from(associatedData));
        let decrypted = decipher.update(encryptedData.encrypted, 'base64', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    } catch (e) { return null; }
}

function hashPassword(password) { return bcrypt.hashSync(password, 12); }
function verifyPassword(password, hash) { return bcrypt.compareSync(password, hash); }

function generateToken(userId) {
    const token = jwt.sign({ userId, exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) }, JWT_SECRET);
    userSessions[token] = { userId, expiresAt: Date.now() + (7 * 24 * 60 * 60 * 1000) };
    saveData();
    return token;
}

function verifyToken(token) {
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (userSessions[token] && userSessions[token].expiresAt > Date.now()) return decoded.userId;
        return null;
    } catch (e) { return null; }
}

function sanitizeInput(str, maxLen = 500) {
    if (!str) return '';
    return str.replace(/[<>]/g, '').substring(0, maxLen);
}

// ============ ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ============
function generateRandomCode() { return crypto.randomBytes(4).toString('hex').toUpperCase(); }
function getFileIcon(ext) {
    const icons = {
        pdf: '📄', mp3: '🎵', html: '🌐', py: '🐍', js: '📜', json: '📦', apk: '📱', jpg: '🖼️', png: '🖼️', gif: '🎞️', mp4: '🎬'
    };
    return icons[ext.toLowerCase()] || '📎';
}

// ============ EXPRESS НАСТРОЙКИ ============
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:", "blob:", "https://ui-avatars.com", "https://i.pinimg.com"],
            connectSrc: ["'self'", "ws:", "wss:"],
            mediaSrc: ["'self'", "data:", "blob:"]
        }
    }
}));
app.use(cors());
app.use(compression());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200, message: { error: 'Слишком много запросов' } });
app.use('/api/', limiter);

// Multer настройки
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        if (file.fieldname === 'avatar') cb(null, AVATAR_DIR);
        else if (file.fieldname === 'sticker') cb(null, STICKER_DIR);
        else cb(null, UPLOAD_DIR);
    },
    filename: (req, file, cb) => cb(null, uuidv4() + path.extname(file.originalname))
});
const upload = multer({
    storage,
    limits: { fileSize: MAX_FILE_SIZE },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'audio/mpeg', 'audio/webm', 'video/mp4', 'application/pdf'];
        cb(null, allowed.includes(file.mimetype));
    }
});

// ============ ПРЕДУСТАНОВЛЕННЫЕ ТЕМАТЫ ============
const TEMAT_CHATS = [
    { id: 'temat_obschestvo', name: 'Общий', avatar: 'https://i.pinimg.com/474x/4b/7b/ce/4b7bcead79dd7f761c37bb50f01bfc51.jpg', description: 'Общий темат для всех' },
    { id: 'temat_nauka', name: 'Наука', avatar: 'https://i.pinimg.com/474x/d7/e1/20/d7e1206b1e0434bcd533eca63f6c9d6b.jpg', description: 'Обсуждаем научные открытия' },
    { id: 'temat_tehnologii', name: 'Технологии', avatar: 'https://cdn-icons-png.flaticon.com/512/7553/7553938.png', description: 'Гаджеты и инновации' },
    { id: 'temat_kultura', name: 'Культура', avatar: 'https://i.pinimg.com/474x/9e/fa/f6/9efaf67c063e360f1d00912c297a8742.jpg', description: 'Искусство, кино, музыка' },
    { id: 'temat_sport', name: 'Спорт', avatar: 'https://media1.tenor.com/m/atsrEuZxjdMAAAAd/orange-juice-drinking.gif', description: 'Спортивные новости и обсуждения' }
];

// Инициализация тематов при первом запуске
TEMAT_CHATS.forEach(temat => {
    if (!chats[temat.id]) {
        chats[temat.id] = {
            id: temat.id,
            type: 'temat',
            name: temat.name,
            avatar: temat.avatar,
            description: temat.description,
            participants: [],
            createdAt: Date.now(),
            encryptedKeys: {},
            public: true
        };
        messages[temat.id] = [];
    }
});

// ============ WEBSOCKET ============
wss.on('connection', (ws, req) => {
    const url = new URL(req.url, `http://${req.headers.host}`);
    const token = url.searchParams.get('token');
    const userId = verifyToken(token);
    
    if (!userId) { ws.close(1008, 'Не авторизован'); return; }
    
    clients.set(userId, ws);
    if (users[userId]) users[userId].lastSeen = Date.now();
    
    ws.on('message', async (data) => {
        try {
            const parsed = JSON.parse(data);
            const { type, chatId, content, targetId, messageId, postId, commentId, reaction, stickerUrl, theme, quizAnswers } = parsed;
            
            const chat = chats[chatId];
            if (!chat) return;
            
            switch (type) {
                case 'typing':
                    if (chat.participants) {
                        chat.participants.forEach(pid => {
                            if (pid !== userId && clients.has(pid)) {
                                clients.get(pid).send(JSON.stringify({ type: 'typing', data: { chatId, userId, userName: users[userId]?.username } }));
                            }
                        });
                    }
                    break;
                    
                case 'read':
                    // Отметка о прочтении
                    break;
                    
                case 'reaction':
                    if (messageId) {
                        const msgIndex = messages[chatId]?.findIndex(m => m.id === messageId);
                        if (msgIndex !== -1 && messages[chatId][msgIndex]) {
                            if (!messages[chatId][msgIndex].reactions) messages[chatId][msgIndex].reactions = {};
                            messages[chatId][msgIndex].reactions[userId] = reaction;
                            saveData();
                            // Рассылаем обновление реакций
                            chat.participants?.forEach(pid => {
                                if (clients.has(pid)) {
                                    clients.get(pid).send(JSON.stringify({ type: 'reaction_update', data: { chatId, messageId, reactions: messages[chatId][msgIndex].reactions } }));
                                }
                            });
                        }
                    }
                    break;
                    
                case 'forward_buffer_add':
                    if (!forwardBuffer[userId]) forwardBuffer[userId] = [];
                    forwardBuffer[userId].push(parsed.message);
                    saveData();
                    break;
                    
                case 'forward_buffer_remove':
                    if (forwardBuffer[userId]) {
                        forwardBuffer[userId] = forwardBuffer[userId].filter((_, i) => i !== parsed.index);
                        saveData();
                    }
                    break;
                    
                case 'theme_change':
                    if (users[userId]) users[userId].theme = theme;
                    saveData();
                    break;
            }
        } catch (e) { console.error('WebSocket error:', e); }
    });
    
    ws.on('close', () => {
        clients.delete(userId);
        if (users[userId]) users[userId].lastSeen = Date.now();
        saveData();
    });
});

// Функция отправки сообщения всем участникам чата
function broadcastToChat(chatId, message, senderId, excludeSender = true) {
    const chat = chats[chatId];
    if (!chat || !chat.participants) return;
    chat.participants.forEach(pid => {
        if (excludeSender && pid === senderId) return;
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify(message));
        }
    });
}

// ============================================
// OKSAGRAM - API ЭНДПОИНТЫ (ПОЛНАЯ ВЕРСИЯ)
// ============================================

// ============ АВТОРИЗАЦИЯ И ПОЛЬЗОВАТЕЛИ ============

// Регистрация
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) return res.status(400).json({ error: 'Заполните все поля' });
    if (username.length < 3 || username.length > 30) return res.status(400).json({ error: 'Имя от 3 до 30 символов' });
    if (password.length < 6) return res.status(400).json({ error: 'Пароль минимум 6 символов' });
    
    const existing = Object.values(users).find(u => u.username === username);
    if (existing) return res.status(400).json({ error: 'Пользователь уже существует' });
    
    const userId = uuidv4();
    users[userId] = {
        id: userId,
        username: sanitizeInput(username),
        passwordHash: hashPassword(password),
        avatar: `https://ui-avatars.com/api/?background=FFDD00&color=000&bold=true&name=${encodeURIComponent(username)}`,
        createdAt: Date.now(),
        lastSeen: Date.now(),
        theme: 'default',
        globalNickname: username,
        teacherAccount: null
    };
    
    const token = generateToken(userId);
    saveData();
    
    res.json({ success: true, token, user: { id: userId, username: users[userId].username, avatar: users[userId].avatar } });
});

// Логин
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    
    const user = Object.values(users).find(u => u.username === username);
    if (!user || !verifyPassword(password, user.passwordHash)) {
        return res.status(401).json({ error: 'Неверное имя или пароль' });
    }
    
    user.lastSeen = Date.now();
    const token = generateToken(user.id);
    saveData();
    
    res.json({ success: true, token, user: { id: user.id, username: user.username, avatar: user.avatar } });
});

// Проверка токена
app.post('/api/verify', (req, res) => {
    const { token } = req.body;
    const userId = verifyToken(token);
    if (!userId || !users[userId]) return res.status(401).json({ error: 'Недействительный токен' });
    
    users[userId].lastSeen = Date.now();
    res.json({ valid: true, user: { id: users[userId].id, username: users[userId].username, avatar: users[userId].avatar } });
});

// Поиск пользователей
app.get('/api/users/search', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const query = (req.query.q || '').toLowerCase();
    const results = Object.values(users)
        .filter(u => u.id !== userId && u.username.toLowerCase().includes(query))
        .slice(0, 20)
        .map(u => ({ id: u.id, username: u.username, avatar: u.avatar }));
    
    res.json(results);
});

// Получение информации о пользователе
app.get('/api/users/:userId', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const user = users[req.params.userId];
    if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
    
    res.json({ id: user.id, username: user.username, avatar: user.avatar, lastSeen: user.lastSeen });
});

// Смена аватара
app.post('/api/users/avatar', upload.single('avatar'), (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    
    users[userId].avatar = `/avatars/${req.file.filename}`;
    saveData();
    res.json({ success: true, avatarUrl: users[userId].avatar });
});

// Смена глобального ника
app.post('/api/users/nickname', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { nickname } = req.body;
    if (!nickname || nickname.length < 3 || nickname.length > 30) {
        return res.status(400).json({ error: 'Ник должен быть от 3 до 30 символов' });
    }
    
    users[userId].globalNickname = sanitizeInput(nickname);
    saveData();
    res.json({ success: true, nickname: users[userId].globalNickname });
});

// ============ ЧАТЫ (ОБЩИЕ) ============

// Создание чата (личный, групповой, канал, школьный, сообщество)
app.post('/api/chats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { type, name, participantIds, adminCode, ownerCode, description, avatar, teacher, students, communityName, communityDescription } = req.body;
    
    let chatId = uuidv4();
    let chatKey = generateAESKey();
    let encryptedKeys = {};
    const allParticipants = [userId, ...(participantIds || [])];
    allParticipants.forEach(pid => { encryptedKeys[pid] = chatKey.toString('base64'); });
    
    let chatName = name || (type === 'private' && participantIds?.length === 1 ? users[participantIds[0]]?.username : 'Новый чат');
    let chatData = {
        id: chatId,
        type: type || 'group',
        name: sanitizeInput(chatName, 50),
        participants: allParticipants,
        createdAt: Date.now(),
        encryptedKeys: encryptedKeys,
        avatar: avatar || `https://ui-avatars.com/api/?background=FFDD00&color=000&bold=true&name=${encodeURIComponent(chatName)}`,
        description: description ? sanitizeInput(description, 200) : '',
        permissions: { participantsCanWrite: true, adminsCanWrite: true, allCanSendFiles: true },
        public: false
    };
    
    // Канал (role-based)
    if (type === 'role-based') {
        chatData.adminCode = adminCode || generateRandomCode();
        chatData.ownerCode = ownerCode || generateRandomCode();
        chatData.subscribers = {};
        chatData.pinnedPosts = [];
    }
    
    // Школьный чат
    if (type === 'school') {
        chatData.teacher = teacher;
        chatData.students = students || [];
        chatData.currentQuiz = null;
        chatData.homeworks = [];
    }
    
    // Сообщество
    if (type === 'community') {
        chatData.adminCode = adminCode || generateRandomCode();
        chatData.ownerCode = ownerCode || generateRandomCode();
        chatData.members = { [userId]: { role: 'owner', joinedAt: Date.now() } };
        chatData.chats = {
            main: {
                id: 'main',
                name: 'Главный чат',
                description: 'Основной чат сообщества',
                type: 'simple',
                createdAt: Date.now()
            }
        };
        chatData.currentCommunityChat = 'main';
    }
    
    chats[chatId] = chatData;
    messages[chatId] = [];
    saveData();
    
    // Уведомляем участников
    allParticipants.forEach(pid => {
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify({ type: 'new_chat', data: { chatId, chatName: chatData.name } }));
        }
    });
    
    res.json({ success: true, chatId, chat: { id: chatId, name: chatData.name, type: chatData.type } });
});

// Получение списка чатов пользователя
app.get('/api/chats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const userChats = Object.values(chats)
        .filter(chat => chat.participants?.includes(userId) || chat.subscribers?.[userId] || chat.members?.[userId])
        .map(chat => ({
            id: chat.id,
            type: chat.type,
            name: chat.name,
            avatar: chat.avatar,
            description: chat.description,
            lastMessage: chat.lastMessage,
            lastMessageTime: chat.lastMessageTime,
            unread: 0,
            public: chat.public,
            participantsCount: chat.participants?.length || Object.keys(chat.subscribers || {}).length || Object.keys(chat.members || {}).length
        }))
        .sort((a, b) => (b.lastMessageTime || 0) - (a.lastMessageTime || 0));
    
    res.json(userChats);
});

// Получение информации о чате
app.get('/api/chats/:chatId', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    res.json({
        id: chat.id,
        type: chat.type,
        name: chat.name,
        avatar: chat.avatar,
        description: chat.description,
        participants: chat.participants || Object.keys(chat.subscribers || {}) || Object.keys(chat.members || {}),
        createdAt: chat.createdAt,
        permissions: chat.permissions,
        public: chat.public,
        attachedChatId: chat.attachedChatId,
        teacher: chat.teacher,
        students: chat.students,
        currentQuiz: chat.currentQuiz ? { title: chat.currentQuiz.title, deadline: chat.currentQuiz.deadline, questionsCount: chat.currentQuiz.questions?.length } : null
    });
});

// Обновление информации о чате
app.put('/api/chats/:chatId', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    const { name, description, avatar, permissions, public: isPublic, attachedChatId } = req.body;
    
    if (name) chat.name = sanitizeInput(name, 50);
    if (description !== undefined) chat.description = sanitizeInput(description, 200);
    if (avatar) chat.avatar = avatar;
    if (permissions && (chat.type === 'role-based' || chat.type === 'school')) chat.permissions = permissions;
    if (isPublic !== undefined && chat.type === 'role-based') chat.public = isPublic;
    if (attachedChatId !== undefined && chat.type === 'role-based') chat.attachedChatId = attachedChatId;
    
    saveData();
    res.json({ success: true });
});

// ============ СООБЩЕНИЯ ============

// Получение сообщений чата
app.get('/api/chats/:chatId/messages', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    // Проверка доступа
    const hasAccess = chat.participants?.includes(userId) || chat.subscribers?.[userId] || chat.members?.[userId];
    if (!hasAccess && !chat.public) return res.status(403).json({ error: 'Нет доступа' });
    
    const chatMessages = messages[chat.id] || [];
    const key = chat.encryptedKeys?.[userId] ? Buffer.from(chat.encryptedKeys[userId], 'base64') : null;
    
    const decryptedMessages = chatMessages.map(msg => {
        if (msg.encrypted && key) {
            const decrypted = decryptMessage(msg.encrypted, key, chat.id);
            return { ...msg, content: decrypted, encrypted: undefined };
        }
        return msg;
    });
    
    res.json(decryptedMessages.slice(-MESSAGE_LIMIT));
});

// Отправка сообщения
app.post('/api/chats/:chatId/messages', upload.single('file'), (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    // Проверка прав на запись
    let canWrite = false;
    if (chat.type === 'simple' || chat.type === 'temat') canWrite = true;
    else if (chat.type === 'role-based') {
        const isSubscribed = chat.subscribers?.[userId];
        const role = isSubscribed?.role || (chat.participants?.includes(userId) ? 'participant' : null);
        if (role === 'owner') canWrite = true;
        else if (role === 'admin') canWrite = chat.permissions?.adminsCanWrite !== false;
        else if (role === 'participant') canWrite = chat.permissions?.participantsCanWrite !== false && isSubscribed;
    }
    else if (chat.type === 'school') {
        if (chat.teacher?.id === userId) canWrite = true;
        else if (chat.students?.some(s => s.id === userId)) canWrite = true;
        else canWrite = false;
    }
    else if (chat.type === 'community') {
        const member = chat.members?.[userId];
        canWrite = !!member;
    }
    
    if (!canWrite) return res.status(403).json({ error: 'Нет прав на отправку сообщений' });
    
    const { content, type, replyTo, important } = req.body;
    const user = users[userId];
    const key = chat.encryptedKeys?.[userId] ? Buffer.from(chat.encryptedKeys[userId], 'base64') : null;
    
    let messageContent = content || '';
    let messageType = type || 'text';
    let fileUrl = null;
    let fileName = null;
    let fileSize = null;
    
    if (req.file) {
        fileUrl = `/uploads/${req.file.filename}`;
        fileName = req.file.originalname;
        fileSize = req.file.size;
        if (req.file.mimetype.startsWith('image/')) messageType = 'photo';
        else if (req.file.mimetype.startsWith('audio/')) messageType = 'audio';
        else if (req.file.mimetype.startsWith('video/')) messageType = 'video';
        else messageType = 'file';
        messageContent = fileUrl;
    }
    
    let encrypted = null;
    if (key && messageType === 'text') {
        encrypted = encryptMessage(messageContent, key, chat.id);
    }
    
    const message = {
        id: uuidv4(),
        type: messageType,
        ...(encrypted ? { encrypted } : { content: messageContent }),
        senderId: userId,
        senderName: user.username,
        senderAvatar: user.avatar,
        timestamp: Date.now(),
        replyTo: replyTo || null,
        important: important === true,
        fileName: fileName,
        fileSize: fileSize,
        reactions: {}
    };
    
    if (!messages[chat.id]) messages[chat.id] = [];
    messages[chat.id].push(message);
    
    if (messages[chat.id].length > MESSAGE_LIMIT) {
        messages[chat.id] = messages[chat.id].slice(-MESSAGE_LIMIT);
    }
    
    // Обновляем последнее сообщение
    let lastMessageText = '';
    if (messageType === 'text') lastMessageText = (messageContent || '').substring(0, 50);
    else if (messageType === 'photo') lastMessageText = '📷 Фото';
    else if (messageType === 'audio') lastMessageText = '🎵 Аудио';
    else if (messageType === 'video') lastMessageText = '🎥 Видео';
    else if (messageType === 'file') lastMessageText = `📎 ${fileName}`;
    else lastMessageText = 'Сообщение';
    
    chat.lastMessage = lastMessageText;
    chat.lastMessageTime = Date.now();
    saveData();
    
    // Рассылка через WebSocket
    const wsMessage = {
        type: 'new_message',
        data: {
            chatId: chat.id,
            message: {
                id: message.id,
                type: messageType,
                content: encrypted ? null : messageContent,
                senderId: userId,
                senderName: user.username,
                senderAvatar: user.avatar,
                timestamp: message.timestamp,
                replyTo: replyTo || null,
                important: important === true,
                fileName: fileName,
                fileSize: fileSize
            }
        }
    };
    
    // Добавляем расшифрованное содержимое для отправителя
    if (encrypted && key) {
        wsMessage.data.message.content = decryptMessage(encrypted, key, chat.id);
    }
    
    const recipients = chat.participants || Object.keys(chat.subscribers || {}) || Object.keys(chat.members || {});
    recipients.forEach(pid => {
        if (clients.has(pid)) {
            // Для получателей нужно расшифровать их ключом
            if (encrypted && pid !== userId && chat.encryptedKeys?.[pid]) {
                const recipientKey = Buffer.from(chat.encryptedKeys[pid], 'base64');
                const decryptedForRecipient = decryptMessage(encrypted, recipientKey, chat.id);
                const recipientMessage = JSON.parse(JSON.stringify(wsMessage));
                recipientMessage.data.message.content = decryptedForRecipient;
                clients.get(pid).send(JSON.stringify(recipientMessage));
            } else {
                clients.get(pid).send(JSON.stringify(wsMessage));
            }
        }
    });
    
    res.json({ success: true, messageId: message.id });
});

// Удаление сообщения
app.delete('/api/chats/:chatId/messages/:messageId', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    const messageIndex = messages[chat.id]?.findIndex(m => m.id === req.params.messageId);
    if (messageIndex === -1) return res.status(404).json({ error: 'Сообщение не найдено' });
    
    const message = messages[chat.id][messageIndex];
    if (message.senderId !== userId) {
        // Проверка на админа/владельца
        let isAdmin = false;
        if (chat.type === 'role-based') {
            const role = chat.subscribers?.[userId]?.role;
            isAdmin = role === 'admin' || role === 'owner';
        } else if (chat.type === 'school') {
            isAdmin = chat.teacher?.id === userId || chat.students?.some(s => s.id === userId);
        }
        if (!isAdmin) return res.status(403).json({ error: 'Нет прав на удаление' });
    }
    
    messages[chat.id].splice(messageIndex, 1);
    saveData();
    
    // Уведомляем участников
    const recipients = chat.participants || Object.keys(chat.subscribers || {}) || Object.keys(chat.members || {});
    recipients.forEach(pid => {
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify({ type: 'message_deleted', data: { chatId: chat.id, messageId: req.params.messageId } }));
        }
    });
    
    res.json({ success: true });
});

// ============================================
// OKSAGRAM - КАНАЛЫ, ПОДПИСКИ, ШКОЛЬНЫЕ ЧАТЫ
// ============================================

// ============ КАНАЛЫ (ROLE-BASED) ============

// Подписка на канал
app.post('/api/channels/:channelId/subscribe', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const channel = chats[req.params.channelId];
    if (!channel || channel.type !== 'role-based') return res.status(404).json({ error: 'Канал не найден' });
    
    if (!channel.subscribers) channel.subscribers = {};
    if (!channel.subscribers[userId]) {
        channel.subscribers[userId] = { subscribedAt: Date.now(), role: 'participant' };
        saveData();
    }
    
    res.json({ success: true, isSubscribed: true });
});

// Отписка от канала
app.delete('/api/channels/:channelId/subscribe', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const channel = chats[req.params.channelId];
    if (!channel || channel.type !== 'role-based') return res.status(404).json({ error: 'Канал не найден' });
    
    if (channel.subscribers && channel.subscribers[userId]) {
        delete channel.subscribers[userId];
        saveData();
    }
    
    res.json({ success: true, isSubscribed: false });
});

// Проверка статуса подписки
app.get('/api/channels/:channelId/subscribe', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const channel = chats[req.params.channelId];
    if (!channel || channel.type !== 'role-based') return res.status(404).json({ error: 'Канал не найден' });
    
    const isSubscribed = !!channel.subscribers?.[userId];
    const role = channel.subscribers?.[userId]?.role || 'none';
    
    res.json({ isSubscribed, role });
});

// Получение публичных каналов (для раздела "Тематы")
app.get('/api/channels/public', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const publicChannels = Object.values(chats)
        .filter(chat => (chat.type === 'role-based' && chat.public === true) || chat.type === 'temat')
        .map(chat => ({
            id: chat.id,
            name: chat.name,
            avatar: chat.avatar,
            description: chat.description,
            subscribersCount: Object.keys(chat.subscribers || {}).length,
            type: chat.type
        }));
    
    res.json(publicChannels);
});

// Вход в канал с ролью
app.post('/api/channels/:channelId/join', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { role, code } = req.body;
    const channel = chats[req.params.channelId];
    if (!channel || (channel.type !== 'role-based' && channel.type !== 'temat')) {
        return res.status(404).json({ error: 'Канал не найден' });
    }
    
    if (channel.type === 'temat') {
        if (!channel.participants) channel.participants = [];
        if (!channel.participants.includes(userId)) {
            channel.participants.push(userId);
            saveData();
        }
        return res.json({ success: true, role: 'participant' });
    }
    
    let assignedRole = null;
    
    if (role === 'owner' && channel.ownerCode === code) {
        assignedRole = 'owner';
    } else if (role === 'admin' && channel.adminCode === code) {
        assignedRole = 'admin';
    } else if (role === 'participant') {
        assignedRole = 'participant';
    } else {
        return res.status(403).json({ error: 'Неверный код доступа' });
    }
    
    if (!channel.subscribers) channel.subscribers = {};
    channel.subscribers[userId] = { subscribedAt: Date.now(), role: assignedRole };
    saveData();
    
    res.json({ success: true, role: assignedRole });
});

// ============ ШКОЛЬНЫЕ ЧАТЫ ============

// Создание школьного чата
app.post('/api/school/create', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { className, teacher, students } = req.body;
    
    if (!className || !teacher?.name || !teacher?.id || !students?.length) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }
    
    const chatId = uuidv4();
    const chatKey = generateAESKey();
    const encryptedKeys = {};
    const allParticipants = [userId, teacher.id, ...students.map(s => s.id)];
    allParticipants.forEach(pid => { encryptedKeys[pid] = chatKey.toString('base64'); });
    
    chats[chatId] = {
        id: chatId,
        type: 'school',
        name: sanitizeInput(className, 50),
        participants: allParticipants,
        createdAt: Date.now(),
        encryptedKeys: encryptedKeys,
        avatar: `https://ui-avatars.com/api/?background=FFDD00&color=000&bold=true&name=${encodeURIComponent(className)}`,
        description: `Школьный чат класса ${className}`,
        teacher: teacher,
        students: students,
        currentQuiz: null,
        homeworks: [],
        permissions: { participantsCanWrite: true, adminsCanWrite: true, allCanSendFiles: true }
    };
    
    messages[chatId] = [];
    saveData();
    
    // Уведомляем всех участников
    allParticipants.forEach(pid => {
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify({ type: 'new_chat', data: { chatId, chatName: chats[chatId].name } }));
        }
    });
    
    res.json({ success: true, chatId });
});

// Назначение домашнего задания
app.post('/api/school/:chatId/homework', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat || chat.type !== 'school') return res.status(404).json({ error: 'Школьный чат не найден' });
    
    // Проверка прав (учитель или ученик-админ)
    const isTeacher = chat.teacher?.id === userId;
    const isStudentAdmin = chat.students?.some(s => s.id === userId);
    if (!isTeacher && !isStudentAdmin) {
        return res.status(403).json({ error: 'Нет прав на назначение ДЗ' });
    }
    
    const { text, deadline } = req.body;
    if (!text) return res.status(400).json({ error: 'Введите текст ДЗ' });
    
    const homework = {
        id: uuidv4(),
        text: sanitizeInput(text, 1000),
        deadline: deadline || null,
        assignedBy: userId,
        assignedAt: Date.now()
    };
    
    if (!chat.homeworks) chat.homeworks = [];
    chat.homeworks.push(homework);
    saveData();
    
    // Отправляем системное сообщение в чат
    const key = chat.encryptedKeys?.[userId] ? Buffer.from(chat.encryptedKeys[userId], 'base64') : null;
    const messageContent = `📚 Домашнее задание от ${users[userId]?.username}:\n\n${text}`;
    let encrypted = null;
    if (key) {
        encrypted = encryptMessage(messageContent, key, chat.id);
    }
    
    const message = {
        id: uuidv4(),
        type: 'text',
        ...(encrypted ? { encrypted } : { content: messageContent }),
        senderId: 'system',
        senderName: '📚 Система',
        timestamp: Date.now(),
        important: true,
        reactions: {}
    };
    
    if (!messages[chat.id]) messages[chat.id] = [];
    messages[chat.id].push(message);
    
    chat.lastMessage = `📚 Домашнее задание`;
    chat.lastMessageTime = Date.now();
    saveData();
    
    // Рассылка
    chat.participants.forEach(pid => {
        if (clients.has(pid)) {
            let msgToSend = { type: 'new_message', data: { chatId: chat.id, message: { ...message, content: messageContent, encrypted: undefined } } };
            if (encrypted && pid !== userId && chat.encryptedKeys?.[pid]) {
                const recipientKey = Buffer.from(chat.encryptedKeys[pid], 'base64');
                const decrypted = decryptMessage(encrypted, recipientKey, chat.id);
                msgToSend.data.message.content = decrypted;
            }
            clients.get(pid).send(JSON.stringify(msgToSend));
        }
    });
    
    res.json({ success: true, homeworkId: homework.id });
});

// Создание ЦДЗ (теста)
app.post('/api/school/:chatId/quiz', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat || chat.type !== 'school') return res.status(404).json({ error: 'Школьный чат не найден' });
    
    const isTeacher = chat.teacher?.id === userId;
    const isStudentAdmin = chat.students?.some(s => s.id === userId);
    if (!isTeacher && !isStudentAdmin) {
        return res.status(403).json({ error: 'Нет прав на создание ЦДЗ' });
    }
    
    const { title, deadline, questions } = req.body;
    if (!title || !questions || !questions.length) {
        return res.status(400).json({ error: 'Заполните название и вопросы' });
    }
    
    chat.currentQuiz = {
        id: uuidv4(),
        title: sanitizeInput(title, 100),
        deadline: deadline || null,
        questions: questions,
        assignedBy: userId,
        assignedAt: Date.now(),
        solved: {}
    };
    saveData();
    
    // Отправляем уведомление
    const key = chat.encryptedKeys?.[userId] ? Buffer.from(chat.encryptedKeys[userId], 'base64') : null;
    const messageContent = `📋 Новое ЦДЗ: ${title}\nДедлайн: ${deadline ? new Date(deadline).toLocaleString() : 'не указан'}\nКоличество вопросов: ${questions.length}`;
    let encrypted = null;
    if (key) {
        encrypted = encryptMessage(messageContent, key, chat.id);
    }
    
    const message = {
        id: uuidv4(),
        type: 'text',
        ...(encrypted ? { encrypted } : { content: messageContent }),
        senderId: 'system',
        senderName: '📋 Система',
        timestamp: Date.now(),
        important: true,
        reactions: {}
    };
    
    if (!messages[chat.id]) messages[chat.id] = [];
    messages[chat.id].push(message);
    chat.lastMessage = `📋 Новое ЦДЗ: ${title}`;
    chat.lastMessageTime = Date.now();
    saveData();
    
    chat.participants.forEach(pid => {
        if (clients.has(pid)) {
            let msgToSend = { type: 'new_message', data: { chatId: chat.id, message: { ...message, content: messageContent, encrypted: undefined } } };
            if (encrypted && pid !== userId && chat.encryptedKeys?.[pid]) {
                const recipientKey = Buffer.from(chat.encryptedKeys[pid], 'base64');
                const decrypted = decryptMessage(encrypted, recipientKey, chat.id);
                msgToSend.data.message.content = decrypted;
            }
            clients.get(pid).send(JSON.stringify(msgToSend));
        }
    });
    
    res.json({ success: true, quizId: chat.currentQuiz.id });
});

// Получение текущего ЦДЗ
app.get('/api/school/:chatId/quiz', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat || chat.type !== 'school') return res.status(404).json({ error: 'Школьный чат не найден' });
    
    if (!chat.currentQuiz) return res.json({ quiz: null });
    
    // Скрываем правильные ответы для учеников
    const isTeacher = chat.teacher?.id === userId;
    const isStudentAdmin = chat.students?.some(s => s.id === userId);
    const isOwner = isTeacher;
    
    let quizToReturn = { ...chat.currentQuiz };
    if (!isTeacher && !isStudentAdmin && !isOwner) {
        quizToReturn = {
            ...quizToReturn,
            questions: quizToReturn.questions.map(q => ({
                ...q,
                correct: undefined,
                keywords: q.type === 'text' ? q.keywords : undefined
            }))
        };
    }
    
    res.json({ quiz: quizToReturn });
});

// Отправка ответов на ЦДЗ
app.post('/api/school/:chatId/quiz/submit', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat || chat.type !== 'school') return res.status(404).json({ error: 'Школьный чат не найден' });
    
    if (!chat.currentQuiz) return res.status(404).json({ error: 'Нет активного ЦДЗ' });
    
    const { answers } = req.body;
    if (!answers) return res.status(400).json({ error: 'Нет ответов' });
    
    // Проверка дедлайна
    if (chat.currentQuiz.deadline && new Date(chat.currentQuiz.deadline).getTime() < Date.now()) {
        return res.status(400).json({ error: 'Дедлайн ЦДЗ истек' });
    }
    
    // Проверка, не сдавал ли уже
    if (chat.currentQuiz.solved[userId]) {
        return res.status(400).json({ error: 'Вы уже сдали это ЦДЗ' });
    }
    
    // Подсчет баллов
    let score = 0;
    const results = [];
    chat.currentQuiz.questions.forEach((q, idx) => {
        const userAnswer = answers[idx];
        let isCorrect = false;
        
        if (q.type === 'choice') {
            isCorrect = userAnswer === q.correct;
        } else if (q.type === 'multiple') {
            const userSet = new Set(userAnswer || []);
            const correctSet = new Set(q.correct);
            isCorrect = userSet.size === correctSet.size && [...userSet].every(v => correctSet.has(v));
        } else if (q.type === 'text') {
            const userAnswerLower = (userAnswer || '').toLowerCase();
            isCorrect = q.keywords.some(kw => userAnswerLower.includes(kw.toLowerCase()));
        }
        
        if (isCorrect) score++;
        results.push({ questionId: idx, isCorrect, userAnswer });
    });
    
    const percentage = (score / chat.currentQuiz.questions.length) * 100;
    const passed = percentage >= 70;
    
    chat.currentQuiz.solved[userId] = {
        score,
        total: chat.currentQuiz.questions.length,
        percentage,
        passed,
        submittedAt: Date.now(),
        results
    };
    saveData();
    
    // Отправляем результат
    const resultMessage = passed ? `✅ Вы сдали ЦДЗ "${chat.currentQuiz.title}"! Результат: ${score}/${chat.currentQuiz.questions.length} (${Math.round(percentage)}%)` 
                                 : `❌ Вы не сдали ЦДЗ "${chat.currentQuiz.title}". Результат: ${score}/${chat.currentQuiz.questions.length} (${Math.round(percentage)}%)`;
    
    const key = chat.encryptedKeys?.[userId] ? Buffer.from(chat.encryptedKeys[userId], 'base64') : null;
    let encrypted = null;
    if (key) {
        encrypted = encryptMessage(resultMessage, key, chat.id);
    }
    
    const message = {
        id: uuidv4(),
        type: 'text',
        ...(encrypted ? { encrypted } : { content: resultMessage }),
        senderId: 'system',
        senderName: '📋 Система',
        timestamp: Date.now(),
        important: false,
        reactions: {}
    };
    
    if (!messages[chat.id]) messages[chat.id] = [];
    messages[chat.id].push(message);
    saveData();
    
    if (clients.has(userId)) {
        clients.get(userId).send(JSON.stringify({ type: 'new_message', data: { chatId: chat.id, message: { ...message, content: resultMessage } } }));
    }
    
    res.json({ success: true, score, total: chat.currentQuiz.questions.length, percentage, passed });
});

// ============ СООБЩЕСТВА ============

// Получение чатов сообщества
app.get('/api/community/:communityId/chats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const community = chats[req.params.communityId];
    if (!community || community.type !== 'community') return res.status(404).json({ error: 'Сообщество не найдено' });
    
    const member = community.members?.[userId];
    if (!member) return res.status(403).json({ error: 'Вы не участник сообщества' });
    
    const communityChats = Object.entries(community.chats || {}).map(([id, chat]) => ({
        id,
        name: chat.name,
        description: chat.description,
        type: chat.type,
        unread: 0
    }));
    
    res.json({ chats: communityChats, userRole: member.role });
});

// Создание чата в сообществе
app.post('/api/community/:communityId/chats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const community = chats[req.params.communityId];
    if (!community || community.type !== 'community') return res.status(404).json({ error: 'Сообщество не найдено' });
    
    const member = community.members?.[userId];
    if (!member || (member.role !== 'admin' && member.role !== 'owner')) {
        return res.status(403).json({ error: 'Нет прав на создание чатов' });
    }
    
    const { name, description } = req.body;
    if (!name) return res.status(400).json({ error: 'Введите название чата' });
    
    const chatId = uuidv4();
    if (!community.chats) community.chats = {};
    community.chats[chatId] = {
        id: chatId,
        name: sanitizeInput(name, 50),
        description: description ? sanitizeInput(description, 200) : '',
        type: 'simple',
        createdAt: Date.now()
    };
    saveData();
    
    // Уведомляем всех участников сообщества
    Object.keys(community.members || {}).forEach(pid => {
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify({ type: 'community_chat_created', data: { communityId: community.id, chatId, chatName: name } }));
        }
    });
    
    res.json({ success: true, chatId });
});

// Получение сообщений чата сообщества
app.get('/api/community/:communityId/chats/:chatId/messages', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const community = chats[req.params.communityId];
    if (!community || community.type !== 'community') return res.status(404).json({ error: 'Сообщество не найдено' });
    
    const member = community.members?.[userId];
    if (!member) return res.status(403).json({ error: 'Вы не участник сообщества' });
    
    const communityMessages = messages[`community_${community.id}_${req.params.chatId}`] || [];
    res.json(communityMessages.slice(-MESSAGE_LIMIT));
});

// Отправка сообщения в чат сообщества
app.post('/api/community/:communityId/chats/:chatId/messages', upload.single('file'), (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const community = chats[req.params.communityId];
    if (!community || community.type !== 'community') return res.status(404).json({ error: 'Сообщество не найдено' });
    
    const member = community.members?.[userId];
    if (!member) return res.status(403).json({ error: 'Вы не участник сообщества' });
    
    const { content, type } = req.body;
    const user = users[userId];
    
    let messageContent = content || '';
    let messageType = type || 'text';
    let fileUrl = null;
    
    if (req.file) {
        fileUrl = `/uploads/${req.file.filename}`;
        if (req.file.mimetype.startsWith('image/')) messageType = 'photo';
        else if (req.file.mimetype.startsWith('audio/')) messageType = 'audio';
        else messageType = 'file';
        messageContent = fileUrl;
    }
    
    const message = {
        id: uuidv4(),
        type: messageType,
        content: messageContent,
        senderId: userId,
        senderName: user.username,
        senderAvatar: user.avatar,
        timestamp: Date.now(),
        reactions: {}
    };
    
    const msgKey = `community_${community.id}_${req.params.chatId}`;
    if (!messages[msgKey]) messages[msgKey] = [];
    messages[msgKey].push(message);
    
    if (messages[msgKey].length > MESSAGE_LIMIT) {
        messages[msgKey] = messages[msgKey].slice(-MESSAGE_LIMIT);
    }
    saveData();
    
    // Рассылка участникам сообщества
    Object.keys(community.members || {}).forEach(pid => {
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify({
                type: 'community_new_message',
                data: { communityId: community.id, chatId: req.params.chatId, message }
            }));
        }
    });
    
    res.json({ success: true });
});

// ============================================
// OKSAGRAM - ТЕМАТЫ, СТИКЕРЫ, ИЗБРАННОЕ, БУФЕР, ПОСТЫ
// ============================================

// ============ ТЕМАТЫ ============

// Получение списка тематов
app.get('/api/temats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const temats = TEMAT_CHATS.map(t => ({
        ...t,
        participantsCount: chats[t.id]?.participants?.length || 0
    }));
    
    res.json(temats);
});

// Присоединение к темату
app.post('/api/temats/:tematId/join', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const temat = chats[req.params.tematId];
    if (!temat || temat.type !== 'temat') return res.status(404).json({ error: 'Темат не найден' });
    
    if (!temat.participants) temat.participants = [];
    if (!temat.participants.includes(userId)) {
        temat.participants.push(userId);
        saveData();
    }
    
    res.json({ success: true });
});

// ============ СТИКЕРЫ ============

// Получение глобальных стикеров
app.get('/api/stickers/global', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    res.json(globalStickers);
});

// Добавление глобального стикера (только для админов)
app.post('/api/stickers/global', upload.single('sticker'), (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    // Проверка на админа (простая: первый пользователь или по особому признаку)
    const isAdmin = Object.keys(users).indexOf(userId) === 0;
    if (!isAdmin) return res.status(403).json({ error: 'Только администратор может добавлять глобальные стикеры' });
    
    if (!req.file) return res.status(400).json({ error: 'Файл не загружен' });
    
    const sticker = {
        id: uuidv4(),
        url: `/stickers/${req.file.filename}`,
        addedBy: userId,
        addedAt: Date.now()
    };
    
    globalStickers.push(sticker);
    saveData();
    
    res.json({ success: true, sticker });
});

// Добавление пользовательского стикера в избранное
app.post('/api/stickers/favorite', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { stickerUrl } = req.body;
    if (!stickerUrl) return res.status(400).json({ error: 'URL стикера обязателен' });
    
    if (!favorites.stickers[userId]) favorites.stickers[userId] = [];
    if (!favorites.stickers[userId].includes(stickerUrl)) {
        favorites.stickers[userId].push(stickerUrl);
        saveData();
    }
    
    res.json({ success: true });
});

// Получение избранных стикеров пользователя
app.get('/api/stickers/favorite', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    res.json(favorites.stickers[userId] || []);
});

// Удаление избранного стикера
app.delete('/api/stickers/favorite', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { stickerUrl } = req.body;
    if (favorites.stickers[userId]) {
        favorites.stickers[userId] = favorites.stickers[userId].filter(s => s !== stickerUrl);
        saveData();
    }
    
    res.json({ success: true });
});

// ============ ИЗБРАННОЕ (ЧАТЫ И СООБЩЕНИЯ) ============

// Добавление чата в избранное
app.post('/api/favorites/chats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { chatId } = req.body;
    if (!chats[chatId]) return res.status(404).json({ error: 'Чат не найден' });
    
    if (!favorites.chats[userId]) favorites.chats[userId] = [];
    if (!favorites.chats[userId].includes(chatId)) {
        favorites.chats[userId].push(chatId);
        saveData();
    }
    
    res.json({ success: true });
});

// Удаление чата из избранного
app.delete('/api/favorites/chats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { chatId } = req.body;
    if (favorites.chats[userId]) {
        favorites.chats[userId] = favorites.chats[userId].filter(id => id !== chatId);
        saveData();
    }
    
    res.json({ success: true });
});

// Получение избранных чатов
app.get('/api/favorites/chats', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const favoriteChats = (favorites.chats[userId] || [])
        .filter(chatId => chats[chatId])
        .map(chatId => ({
            id: chatId,
            name: chats[chatId].name,
            avatar: chats[chatId].avatar,
            type: chats[chatId].type,
            lastMessage: chats[chatId].lastMessage
        }));
    
    res.json(favoriteChats);
});

// Добавление сообщения в избранное
app.post('/api/favorites/messages', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { chatId, messageId } = req.body;
    const chatMessages = messages[chatId];
    if (!chatMessages) return res.status(404).json({ error: 'Сообщение не найдено' });
    
    const message = chatMessages.find(m => m.id === messageId);
    if (!message) return res.status(404).json({ error: 'Сообщение не найдено' });
    
    if (!favorites.messages[userId]) favorites.messages[userId] = [];
    if (!favorites.messages[userId].some(m => m.id === messageId)) {
        favorites.messages[userId].push({
            id: messageId,
            chatId: chatId,
            type: message.type,
            content: message.content,
            senderName: message.senderName,
            timestamp: message.timestamp,
            savedAt: Date.now()
        });
        saveData();
    }
    
    res.json({ success: true });
});

// Удаление сообщения из избранного
app.delete('/api/favorites/messages', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { messageId } = req.body;
    if (favorites.messages[userId]) {
        favorites.messages[userId] = favorites.messages[userId].filter(m => m.id !== messageId);
        saveData();
    }
    
    res.json({ success: true });
});

// Получение избранных сообщений
app.get('/api/favorites/messages', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    res.json(favorites.messages[userId] || []);
});

// ============ БУФЕР ПЕРЕСЫЛКИ ============

// Получение буфера пересылки
app.get('/api/forward-buffer', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    res.json(forwardBuffer[userId] || []);
});

// Добавление в буфер пересылки
app.post('/api/forward-buffer', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { message } = req.body;
    if (!forwardBuffer[userId]) forwardBuffer[userId] = [];
    forwardBuffer[userId].push({ ...message, addedAt: Date.now() });
    saveData();
    
    res.json({ success: true });
});

// Удаление из буфера пересылки
app.delete('/api/forward-buffer/:index', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const index = parseInt(req.params.index);
    if (forwardBuffer[userId] && forwardBuffer[userId][index]) {
        forwardBuffer[userId].splice(index, 1);
        saveData();
    }
    
    res.json({ success: true });
});

// Очистка буфера пересылки
app.delete('/api/forward-buffer', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    forwardBuffer[userId] = [];
    saveData();
    
    res.json({ success: true });
});

// ============ ПОСТЫ ============

// Создание поста
app.post('/api/chats/:chatId/posts', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    // Проверка прав на создание постов (админ/владелец/учитель)
    let canCreatePost = false;
    if (chat.type === 'role-based') {
        const role = chat.subscribers?.[userId]?.role;
        canCreatePost = role === 'admin' || role === 'owner';
    } else if (chat.type === 'school') {
        canCreatePost = chat.teacher?.id === userId || chat.students?.some(s => s.id === userId);
    } else if (chat.type === 'temat') {
        canCreatePost = true;
    }
    
    if (!canCreatePost) {
        return res.status(403).json({ error: 'Нет прав на создание постов' });
    }
    
    const { content, attachments, important } = req.body;
    if (!content && (!attachments || !attachments.length)) {
        return res.status(400).json({ error: 'Пост не может быть пустым' });
    }
    
    const user = users[userId];
    const key = chat.encryptedKeys?.[userId] ? Buffer.from(chat.encryptedKeys[userId], 'base64') : null;
    
    let encrypted = null;
    if (key && content) {
        encrypted = encryptMessage(content, key, chat.id);
    }
    
    const post = {
        id: uuidv4(),
        type: 'post',
        ...(encrypted ? { encrypted } : { content: content || '' }),
        senderId: userId,
        senderName: user.username,
        senderAvatar: user.avatar,
        timestamp: Date.now(),
        attachments: attachments || [],
        important: important === true,
        likes: {},
        comments: [],
        pinned: false
    };
    
    if (!messages[chat.id]) messages[chat.id] = [];
    messages[chat.id].push(post);
    
    if (messages[chat.id].length > MESSAGE_LIMIT) {
        messages[chat.id] = messages[chat.id].slice(-MESSAGE_LIMIT);
    }
    
    chat.lastMessage = `📝 Пост: ${(content || '').substring(0, 30)}`;
    chat.lastMessageTime = Date.now();
    saveData();
    
    // Рассылка
    const recipients = chat.participants || Object.keys(chat.subscribers || {}) || Object.keys(chat.members || {});
    recipients.forEach(pid => {
        if (clients.has(pid)) {
            let postToSend = { ...post };
            if (encrypted && pid !== userId && chat.encryptedKeys?.[pid]) {
                const recipientKey = Buffer.from(chat.encryptedKeys[pid], 'base64');
                const decrypted = decryptMessage(encrypted, recipientKey, chat.id);
                postToSend.content = decrypted;
                postToSend.encrypted = undefined;
            } else if (encrypted && pid === userId) {
                postToSend.content = decryptMessage(encrypted, key, chat.id);
                postToSend.encrypted = undefined;
            }
            clients.get(pid).send(JSON.stringify({ type: 'new_post', data: { chatId: chat.id, post: postToSend } }));
        }
    });
    
    res.json({ success: true, postId: post.id });
});

// Лайк поста
app.post('/api/chats/:chatId/posts/:postId/like', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    const postIndex = messages[chat.id]?.findIndex(m => m.id === req.params.postId && m.type === 'post');
    if (postIndex === -1) return res.status(404).json({ error: 'Пост не найден' });
    
    const post = messages[chat.id][postIndex];
    if (post.likes[userId]) {
        delete post.likes[userId];
    } else {
        post.likes[userId] = Date.now();
    }
    saveData();
    
    const recipients = chat.participants || Object.keys(chat.subscribers || {}) || Object.keys(chat.members || {});
    recipients.forEach(pid => {
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify({ type: 'post_like_update', data: { chatId: chat.id, postId: post.id, likes: Object.keys(post.likes).length } }));
        }
    });
    
    res.json({ success: true, likesCount: Object.keys(post.likes).length, isLiked: !!post.likes[userId] });
});

// Добавление комментария к посту
app.post('/api/chats/:chatId/posts/:postId/comments', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    const postIndex = messages[chat.id]?.findIndex(m => m.id === req.params.postId && m.type === 'post');
    if (postIndex === -1) return res.status(404).json({ error: 'Пост не найден' });
    
    const { text } = req.body;
    if (!text) return res.status(400).json({ error: 'Введите текст комментария' });
    
    const user = users[userId];
    const comment = {
        id: uuidv4(),
        text: sanitizeInput(text, 500),
        senderId: userId,
        senderName: user.username,
        senderAvatar: user.avatar,
        timestamp: Date.now(),
        likes: {}
    };
    
    messages[chat.id][postIndex].comments.push(comment);
    saveData();
    
    const recipients = chat.participants || Object.keys(chat.subscribers || {}) || Object.keys(chat.members || {});
    recipients.forEach(pid => {
        if (clients.has(pid)) {
            clients.get(pid).send(JSON.stringify({ type: 'new_comment', data: { chatId: chat.id, postId: post.id, comment } }));
        }
    });
    
    res.json({ success: true, comment });
});

// Закрепление поста (только для админов/владельцев)
app.post('/api/chats/:chatId/posts/:postId/pin', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    // Проверка прав
    let canPin = false;
    if (chat.type === 'role-based') {
        const role = chat.subscribers?.[userId]?.role;
        canPin = role === 'admin' || role === 'owner';
    } else if (chat.type === 'school') {
        canPin = chat.teacher?.id === userId || chat.students?.some(s => s.id === userId);
    } else if (chat.type === 'temat') {
        canPin = true;
    }
    
    if (!canPin) return res.status(403).json({ error: 'Нет прав на закрепление постов' });
    
    const postIndex = messages[chat.id]?.findIndex(m => m.id === req.params.postId && m.type === 'post');
    if (postIndex === -1) return res.status(404).json({ error: 'Пост не найден' });
    
    messages[chat.id][postIndex].pinned = !messages[chat.id][postIndex].pinned;
    saveData();
    
    res.json({ success: true, pinned: messages[chat.id][postIndex].pinned });
});

// ============ QR-КОДЫ И ИНВАЙТ-ССЫЛКИ ============

// Получение инвайт-ссылки
app.get('/api/chats/:chatId/invite', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const chat = chats[req.params.chatId];
    if (!chat) return res.status(404).json({ error: 'Чат не найден' });
    
    const inviteLink = `${req.protocol}://${req.get('host')}/?join=${chat.id}`;
    res.json({ inviteLink });
});

// ============ ТЕМЫ ОФОРМЛЕНИЯ ============

// Получение темы пользователя
app.get('/api/users/theme', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const theme = users[userId]?.theme || 'default';
    res.json({ theme });
});

// Смена темы
app.post('/api/users/theme', (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    const userId = verifyToken(token);
    if (!userId) return res.status(401).json({ error: 'Не авторизован' });
    
    const { theme } = req.body;
    const validThemes = ['default', 'ios', 'whatsapp', 'telegram', 'dark'];
    if (!validThemes.includes(theme)) {
        return res.status(400).json({ error: 'Неверная тема' });
    }
    
    users[userId].theme = theme;
    saveData();
    
    res.json({ success: true, theme });
});

// ============ СТАТИЧЕСКИЕ ФАЙЛЫ ============
app.use('/uploads', express.static(UPLOAD_DIR));
app.use('/avatars', express.static(AVATAR_DIR));
app.use('/stickers', express.static(STICKER_DIR));

// ============ ЗАПУСК СЕРВЕРА ============
server.listen(PORT, () => {
    console.log(`\n🚀 OKSAGRAM - ПОЛНАЯ ВЕРСИЯ ЗАПУЩЕНА`);
    console.log(`📍 http://localhost:${PORT}`);
    console.log(`🔒 Шифрование: AES-256-GCM`);
    console.log(`📱 Поддерживаются: каналы, сообщества, школьные чаты, тематы`);
    console.log(`✅ Регистрация и личные чаты включены\n`);
});