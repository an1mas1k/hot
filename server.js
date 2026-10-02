const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parse: parseUrl } = require('url');

const PORT = process.env.PORT || 3000;
const USERS_FILE = path.join(__dirname, 'users.json');
const POSTS_FILE = path.join(__dirname, 'posts.json');
const DM_FILE = path.join(__dirname, 'dm.json');
const CHANNELS_FILE = path.join(__dirname, 'channels.json');
const CHATS_FILE = path.join(__dirname, 'chats.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');
const HTML_FILE = path.join(__dirname, 'index.html');

const MAX_BODY_SIZE = 14 * 1024 * 1024;
const POSTS_PER_WALL = 100;
const FEED_LIMIT = 100;
const DM_HISTORY_LIMIT = 300;
const HANDLE_RE = /^[a-zA-Z0-9_]{3,20}$/;
const SESSION_TTL = 30 * 24 * 60 * 60 * 1000; // 30 дней

const callSignals = {};
function pushCallSignal(toUser, signal) {
    const key = toUser.toLowerCase();
    if (!callSignals[key]) callSignals[key] = [];
    callSignals[key].push(signal);
}
function popCallSignals(user) {
    const key = user.toLowerCase();
    const signals = callSignals[key] || [];
    callSignals[key] = [];
    return signals;
}

function ensureFile(filePath) { if (!fs.existsSync(filePath)) fs.writeFileSync(filePath, '[]', 'utf8'); }
[USERS_FILE, POSTS_FILE, DM_FILE, CHANNELS_FILE, CHATS_FILE, SESSIONS_FILE].forEach(ensureFile);

function readJSON(fp) { try { return JSON.parse(fs.readFileSync(fp, 'utf8') || '[]'); } catch (e) { return []; } }
function writeJSON(fp, data) { fs.writeFileSync(fp, JSON.stringify(data, null, 2), 'utf8'); }

function readUsers() { return readJSON(USERS_FILE); }
function saveUsers(u) { writeJSON(USERS_FILE, u); }
function readPosts() { return readJSON(POSTS_FILE); }
function savePosts(p) { writeJSON(POSTS_FILE, p); }
function readDms() { return readJSON(DM_FILE); }
function saveDms(d) { writeJSON(DM_FILE, d); }
function readChannels() { return readJSON(CHANNELS_FILE); }
function saveChannels(c) { writeJSON(CHANNELS_FILE, c); }
function readChats() { return readJSON(CHATS_FILE); }
function saveChats(c) { writeJSON(CHATS_FILE, c); }
function readSessions() { return readJSON(SESSIONS_FILE); }
function saveSessions(s) { writeJSON(SESSIONS_FILE, s); }

function normalizeHandle(raw) { return (raw || '').trim().replace(/^@+/, ''); }
function dmKey(a, b) { return [String(a).toLowerCase(), String(b).toLowerCase()].sort().join('::'); }
function makeId() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 8); }

function hashPassword(password, salt) {
    return crypto.scryptSync(password, salt, 64).toString('hex');
}
function generateSalt() { return crypto.randomBytes(16).toString('hex'); }
function generateToken() { return crypto.randomBytes(32).toString('hex'); }

function createSession(username) {
    const sessions = readSessions().filter(s => Date.now() - s.createdAt < SESSION_TTL);
    const token = generateToken();
    sessions.push({ token, username, createdAt: Date.now() });
    saveSessions(sessions);
    return token;
}
function getSessionUser(token) {
    if (!token) return null;
    const sessions = readSessions();
    const s = sessions.find(x => x.token === token);
    if (!s) return null;
    if (Date.now() - s.createdAt > SESSION_TTL) return null;
    const users = readUsers();
    return users.find(u => u.username.toLowerCase() === s.username.toLowerCase()) || null;
}
function destroySession(token) {
    if (!token) return;
    const sessions = readSessions().filter(s => s.token !== token);
    saveSessions(sessions);
}
function destroyUserSessions(username) {
    const sessions = readSessions().filter(s => s.username.toLowerCase() !== username.toLowerCase());
    saveSessions(sessions);
}

function sendJSON(res, status, data) {
    res.writeHead(status, {
        'Content-Type': 'application/json; charset=utf-8',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS'
    });
    res.end(JSON.stringify(data));
}
function readBody(req) {
    return new Promise(function (resolve, reject) {
        let body = '';
        req.on('data', function (chunk) {
            body += chunk;
            if (body.length > MAX_BODY_SIZE) { reject(new Error('Слишком большой запрос')); req.destroy(); }
        });
        req.on('end', function () {
            try { resolve(body ? JSON.parse(body) : {}); }
            catch (e) { reject(new Error('Некорректный JSON')); }
        });
        req.on('error', reject);
    });
}
function getToken(req) {
    const auth = req.headers['authorization'] || '';
    if (auth.startsWith('Bearer ')) return auth.slice(7);
    return null;
}
// Возвращает пользователя по токену, или null
function authUser(req) {
    return getSessionUser(getToken(req));
}

/* ========== AUTH ========== */

async function handleRegister(req, res) {
    try {
        const data = await readBody(req);
        const username = (data.username || '').trim();
        const email = (data.email || '').trim().replace(/[\s\u00A0\u200B\uFEFF]/g, '');
        const password = data.password || '';
        if (username.length < 3) return sendJSON(res, 400, { error: 'Имя — минимум 3 символа' });
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return sendJSON(res, 400, { error: 'Некорректный email' });
        if (password.length < 6) return sendJSON(res, 400, { error: 'Пароль — минимум 6 символов' });
        const users = readUsers();
        if (users.some(u => u.username.toLowerCase() === username.toLowerCase())) return sendJSON(res, 409, { error: 'Такое имя уже занято' });
        if (users.some(u => u.email.toLowerCase() === email.toLowerCase())) return sendJSON(res, 409, { error: 'Эта почта уже зарегистрирована' });
        const salt = generateSalt();
        const newUser = {
            username, email, salt,
            passwordHash: hashPassword(password, salt),
            avatar: '', handle: '', theme: 'dark', wallpaper: '', birthday: '',
            friends: [], incomingRequests: [], blocked: [],
            createdAt: new Date().toISOString(), lastSeen: new Date().toISOString()
        };
        users.push(newUser);
        saveUsers(users);
        const token = createSession(newUser.username);
        sendJSON(res, 201, {
            token,
            user: {
                username: newUser.username, email: newUser.email, avatar: '', handle: '',
                theme: 'dark', wallpaper: '', birthday: '',
                friends: [], incomingRequests: [], blocked: []
            }
        });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

async function handleLogin(req, res) {
    try {
        const data = await readBody(req);
        const login = (data.login || '').trim().toLowerCase();
        const password = data.password || '';
        if (!login || !password) return sendJSON(res, 400, { error: 'Введите логин и пароль' });
        const users = readUsers();
        const user = users.find(u => u.username.toLowerCase() === login || u.email.toLowerCase() === login);
        if (!user) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        if (hashPassword(password, user.salt) !== user.passwordHash) return sendJSON(res, 401, { error: 'Неверный пароль' });
        user.lastSeen = new Date().toISOString();
        saveUsers(users);
        const token = createSession(user.username);
        sendJSON(res, 200, {
            token,
            user: {
                username: user.username, email: user.email, avatar: user.avatar || '',
                handle: user.handle || '', theme: user.theme || 'dark',
                wallpaper: user.wallpaper || '', birthday: user.birthday || '',
                friends: user.friends || [], incomingRequests: user.incomingRequests || [],
                blocked: user.blocked || []
            }
        });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

// Восстановление сессии по токену
function handleSession(req, res) {
    const token = getToken(req);
    const user = getSessionUser(token);
    if (!user) return sendJSON(res, 401, { error: 'Сессия истекла' });
    sendJSON(res, 200, {
        token,
        user: {
            username: user.username, email: user.email, avatar: user.avatar || '',
            handle: user.handle || '', theme: user.theme || 'dark',
            wallpaper: user.wallpaper || '', birthday: user.birthday || '',
            friends: user.friends || [], incomingRequests: user.incomingRequests || [],
            blocked: user.blocked || []
        }
    });
}

function handleLogout(req, res) {
    const token = getToken(req);
    destroySession(token);
    sendJSON(res, 200, { ok: true });
}

/* ========== HEARTBEAT / STATUS ========== */

async function handleHeartbeat(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const users = readUsers();
        const user = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
        if (user) {
            user.lastSeen = new Date().toISOString();
            saveUsers(users);
            const dms = readDms();
            let changed = false;
            dms.forEach(m => { if (m.to && m.to.toLowerCase() === me.username.toLowerCase() && !m.delivered) { m.delivered = true; changed = true; } });
            if (changed) saveDms(dms);
        }
        sendJSON(res, 200, { ok: true });
    } catch (e) { sendJSON(res, 500, { error: 'Error' }); }
}
function handleUserStatus(req, res, query) {
    const target = (query.username || '').trim().toLowerCase();
    const u = readUsers().find(x => x.username.toLowerCase() === target);
    if (!u) return sendJSON(res, 404, { error: 'User not found' });
    sendJSON(res, 200, { lastSeen: u.lastSeen || u.createdAt });
}

/* ========== CALLS ========== */

async function handleCallSignalSend(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const { to, type, sdp, candidate } = data;
        const from = me.username;
        if (!to || !type) return sendJSON(res, 400, { error: 'Missing call params' });
        const users = readUsers();
        const fromU = users.find(u => u.username.toLowerCase() === String(from).toLowerCase());
        const toU = users.find(u => u.username.toLowerCase() === String(to).toLowerCase());
        if (fromU && toU) {
            if ((fromU.blocked || []).some(b => b.toLowerCase() === String(to).toLowerCase())) return sendJSON(res, 403, { error: 'Вы заблокировали этого пользователя' });
            if ((toU.blocked || []).some(b => b.toLowerCase() === String(from).toLowerCase())) return sendJSON(res, 403, { error: 'Пользователь заблокировал вас' });
        }
        pushCallSignal(to, { from, to, type, sdp, candidate, time: Date.now() });
        sendJSON(res, 200, { ok: true });
    } catch (e) { sendJSON(res, 500, { error: 'Error' }); }
}
function handleCallSignalPoll(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    sendJSON(res, 200, { signals: popCallSignals(me.username) });
}

async function handleCallLog(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const from = me.username;
        const to = (data.to || '').trim();
        const type = (data.type || '').trim();
        const duration = parseInt(data.duration || 0, 10) || 0;
        if (!to || !type) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        if (!['outgoing', 'incoming', 'missed', 'cancelled', 'declined'].includes(type)) return sendJSON(res, 400, { error: 'Неизвестный тип звонка' });
        const msg = { id: makeId(), from, to, type: 'call', callType: type, duration, delivered: true, read: true, createdAt: new Date().toISOString() };
        const dms = readDms();
        dms.push(msg);
        saveDms(dms.length > 5000 ? dms.slice(-5000) : dms);
        sendJSON(res, 201, { message: msg });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

/* ========== BLOCK ========== */

async function handleBlockToggle(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const target = (data.target || '').trim();
        if (!target) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        if (me.username.toLowerCase() === target.toLowerCase()) return sendJSON(res, 400, { error: 'Нельзя заблокировать себя' });
        const users = readUsers();
        const meUser = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
        const targetUser = users.find(u => u.username.toLowerCase() === target.toLowerCase());
        if (!meUser || !targetUser) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        if (!Array.isArray(meUser.blocked)) meUser.blocked = [];
        const lowerTarget = targetUser.username.toLowerCase();
        const idx = meUser.blocked.findIndex(b => b.toLowerCase() === lowerTarget);
        let blocked;
        if (idx === -1) { meUser.blocked.push(targetUser.username); blocked = true; }
        else { meUser.blocked.splice(idx, 1); blocked = false; }
        saveUsers(users);
        sendJSON(res, 200, { blocked, blockedList: meUser.blocked });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
function handleBlockedList(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const users = readUsers();
    const meUser = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
    if (!meUser) return sendJSON(res, 404, { error: 'Пользователь не найден' });
    const blockedNames = Array.isArray(meUser.blocked) ? meUser.blocked : [];
    const list = users
        .filter(u => blockedNames.some(b => b.toLowerCase() === u.username.toLowerCase()))
        .map(u => ({ username: u.username, avatar: u.avatar || '', handle: u.handle || '' }));
    sendJSON(res, 200, { blocked: list });
}
function handleBlockStatus(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const target = (query.target || '').trim().toLowerCase();
    const users = readUsers();
    const meUser = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
    const targetUser = users.find(u => u.username.toLowerCase() === target);
    if (!meUser || !targetUser) return sendJSON(res, 404, { error: 'Пользователь не найден' });
    const iBlocked = (meUser.blocked || []).some(b => b.toLowerCase() === target);
    const heBlocked = (targetUser.blocked || []).some(b => b.toLowerCase() === me.username.toLowerCase());
    sendJSON(res, 200, { iBlocked, heBlocked, mutual: iBlocked || heBlocked });
}

/* ========== FORWARD ========== */

async function handleForward(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const to = (data.to || '').trim();
        const text = (data.text || '').trim();
        const originalFrom = (data.originalFrom || '').trim();
        if (!to || !text) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const users = readUsers();
        const sender = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
        const recipient = users.find(u => u.username.toLowerCase() === to.toLowerCase());
        if (!sender || !recipient) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        if ((sender.blocked || []).some(b => b.toLowerCase() === to.toLowerCase())) return sendJSON(res, 403, { error: 'Вы заблокировали этого пользователя' });
        if ((recipient.blocked || []).some(b => b.toLowerCase() === me.username.toLowerCase())) return sendJSON(res, 403, { error: 'Пользователь заблокировал вас' });
        const isOnline = recipient.lastSeen && (Date.now() - new Date(recipient.lastSeen).getTime() < 35000);
        const message = {
            id: makeId(), from: sender.username, to: recipient.username, text,
            forwardedFrom: originalFrom || null,
            delivered: !!isOnline, read: false, createdAt: new Date().toISOString()
        };
        const dms = readDms();
        dms.push(message);
        saveDms(dms.length > 5000 ? dms.slice(-5000) : dms);
        sendJSON(res, 201, { message });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

/* ========== PROFILE ========== */

async function handleUpdateProfile(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const newUsername = (data.newUsername || '').trim();
        const hasAvatar = Object.prototype.hasOwnProperty.call(data, 'avatar');
        const avatar = data.avatar;
        const hasHandle = Object.prototype.hasOwnProperty.call(data, 'handle');
        const handle = hasHandle ? normalizeHandle(typeof data.handle === 'string' ? data.handle : '') : null;
        const hasTheme = Object.prototype.hasOwnProperty.call(data, 'theme');
        const theme = hasTheme && (data.theme === 'light' || data.theme === 'dark') ? data.theme : null;
        const hasWallpaper = Object.prototype.hasOwnProperty.call(data, 'wallpaper');
        const wallpaper = hasWallpaper && typeof data.wallpaper === 'string' ? data.wallpaper : null;
        const hasBirthday = Object.prototype.hasOwnProperty.call(data, 'birthday');
        const birthdayRaw = hasBirthday && typeof data.birthday === 'string' ? data.birthday.trim() : '';
        if (hasBirthday && birthdayRaw && !/^\d{4}-\d{2}-\d{2}$/.test(birthdayRaw)) return sendJSON(res, 400, { error: 'Некорректная дата рождения' });
        if (hasBirthday && birthdayRaw) {
            const [y, m, d] = birthdayRaw.split('-').map(Number);
            const dt = new Date(Date.UTC(y, m - 1, d));
            if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) return sendJSON(res, 400, { error: 'Некорректная дата рождения' });
            if (dt.getTime() > Date.now()) return sendJSON(res, 400, { error: 'Некорректная дата рождения' });
        }
        if (newUsername.length < 3 || newUsername.length > 20) return sendJSON(res, 400, { error: 'Ник — от 3 до 20 символов' });
        if (hasAvatar && typeof avatar === 'string' && avatar.length > MAX_BODY_SIZE) return sendJSON(res, 400, { error: 'Аватар слишком большой' });
        if (hasHandle && handle && !HANDLE_RE.test(handle)) return sendJSON(res, 400, { error: 'Юзернейм: 3-20 символов, латиница, цифры и _' });
        const users = readUsers();
        const user = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
        if (!user) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        const lowerNewName = newUsername.toLowerCase();
        const lowerOldName = user.username.toLowerCase();
        const usernameChanged = lowerNewName !== lowerOldName;
        const avatarChanged = hasAvatar && avatar !== user.avatar;
        if (usernameChanged && users.some(u => u !== user && u.username.toLowerCase() === lowerNewName)) return sendJSON(res, 409, { error: 'Такое имя уже занято' });
        if (hasHandle && handle && users.some(u => u !== user && (u.handle || '').toLowerCase() === handle.toLowerCase())) return sendJSON(res, 409, { error: 'Такой юзернейм уже занят' });
        user.username = newUsername;
        if (hasAvatar) user.avatar = typeof avatar === 'string' ? avatar : '';
        if (hasHandle) user.handle = handle;
        if (hasTheme && theme) user.theme = theme;
        if (hasWallpaper) user.wallpaper = wallpaper;
        if (hasBirthday) user.birthday = birthdayRaw;
        if (usernameChanged) {
            users.forEach(u => {
                if (Array.isArray(u.friends)) u.friends = u.friends.map(f => f.toLowerCase() === lowerOldName ? newUsername : f);
                if (Array.isArray(u.incomingRequests)) u.incomingRequests = u.incomingRequests.map(r => r.toLowerCase() === lowerOldName ? newUsername : r);
                if (Array.isArray(u.blocked)) u.blocked = u.blocked.map(b => b.toLowerCase() === lowerOldName ? newUsername : b);
            });
        }
        saveUsers(users);
        if (usernameChanged) {
            const sessions = readSessions();
            let sc = false;
            sessions.forEach(s => { if (s.username.toLowerCase() === lowerOldName) { s.username = newUsername; sc = true; } });
            if (sc) saveSessions(sessions);
        }
        if (usernameChanged || avatarChanged) {
            if (usernameChanged) {
                const dms = readDms();
                let changed = false;
                dms.forEach(m => {
                    if (m.from && m.from.toLowerCase() === lowerOldName) { m.from = newUsername; changed = true; }
                    if (m.to && m.to.toLowerCase() === lowerOldName) { m.to = newUsername; changed = true; }
                });
                if (changed) saveDms(dms);
            }
            const posts = readPosts();
            let pc = false;
            posts.forEach(p => {
                if (p.username.toLowerCase() === lowerOldName) { p.username = newUsername; if (avatarChanged) p.avatar = user.avatar; pc = true; }
                if (p.repostOf && p.repostOf.username && p.repostOf.username.toLowerCase() === lowerOldName) { p.repostOf.username = newUsername; if (avatarChanged) p.repostOf.avatar = user.avatar; pc = true; }
                if (Array.isArray(p.likes)) { const i = p.likes.findIndex(l => l.toLowerCase() === lowerOldName); if (i !== -1) { p.likes[i] = newUsername; pc = true; } }
                if (Array.isArray(p.comments)) p.comments.forEach(c => { if (c.username.toLowerCase() === lowerOldName) { c.username = newUsername; if (avatarChanged) c.avatar = user.avatar; pc = true; } });
            });
            if (pc) savePosts(posts);
            const channels = readChannels();
            let cc = false;
            channels.forEach(ch => {
                if (ch.owner.toLowerCase() === lowerOldName) { ch.owner = newUsername; cc = true; }
                if (Array.isArray(ch.members)) { const i = ch.members.findIndex(m => m.toLowerCase() === lowerOldName); if (i !== -1) { ch.members[i] = newUsername; cc = true; } }
            });
            if (cc) saveChannels(channels);
            const chats = readChats();
            let chc = false;
            chats.forEach(ch => {
                if (ch.owner.toLowerCase() === lowerOldName) { ch.owner = newUsername; chc = true; }
                if (Array.isArray(ch.members)) { const i = ch.members.findIndex(m => m.toLowerCase() === lowerOldName); if (i !== -1) { ch.members[i] = newUsername; chc = true; } }
                if (Array.isArray(ch.messages)) ch.messages.forEach(msg => {
                    if (msg.from && msg.from.toLowerCase() === lowerOldName) { msg.from = newUsername; chc = true; }
                    if (Array.isArray(msg.read)) msg.read = msg.read.map(r => r.toLowerCase() === lowerOldName ? newUsername : r);
                });
            });
            if (chc) saveChats(chats);
        }
        sendJSON(res, 200, {
            user: {
                username: user.username, email: user.email, avatar: user.avatar || '',
                handle: user.handle || '', theme: user.theme || 'dark',
                wallpaper: user.wallpaper || '', birthday: user.birthday || '',
                friends: user.friends || [], blocked: user.blocked || []
            }
        });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

/* ========== FRIENDS ========== */

async function handleFriendAction(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const target = (data.target || '').trim();
        const action = (data.action || '').trim();
        if (!target || !action) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        if (me.username.toLowerCase() === target.toLowerCase()) return sendJSON(res, 400, { error: 'Нельзя выполнить действие с собой' });
        const users = readUsers();
        const meUser = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
        const targetUser = users.find(u => u.username.toLowerCase() === target.toLowerCase());
        if (!meUser || !targetUser) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        if (!Array.isArray(meUser.friends)) meUser.friends = [];
        if (!Array.isArray(targetUser.friends)) targetUser.friends = [];
        if (!Array.isArray(meUser.incomingRequests)) meUser.incomingRequests = [];
        if (!Array.isArray(targetUser.incomingRequests)) targetUser.incomingRequests = [];
        const lowerMe = meUser.username.toLowerCase();
        const lowerTarget = targetUser.username.toLowerCase();
        if (action === 'send') {
            if ((meUser.blocked || []).some(b => b.toLowerCase() === lowerTarget)) return sendJSON(res, 403, { error: 'Вы заблокировали этого пользователя' });
            if ((targetUser.blocked || []).some(b => b.toLowerCase() === lowerMe)) return sendJSON(res, 403, { error: 'Пользователь заблокировал вас' });
            if (!targetUser.incomingRequests.some(r => r.toLowerCase() === lowerMe)) targetUser.incomingRequests.push(meUser.username);
        } else if (action === 'cancel') {
            targetUser.incomingRequests = targetUser.incomingRequests.filter(r => r.toLowerCase() !== lowerMe);
        } else if (action === 'accept') {
            meUser.incomingRequests = meUser.incomingRequests.filter(r => r.toLowerCase() !== lowerTarget);
            if (!meUser.friends.some(f => f.toLowerCase() === lowerTarget)) meUser.friends.push(targetUser.username);
            if (!targetUser.friends.some(f => f.toLowerCase() === lowerMe)) targetUser.friends.push(meUser.username);
        } else if (action === 'decline') {
            meUser.incomingRequests = meUser.incomingRequests.filter(r => r.toLowerCase() !== lowerTarget);
        } else if (action === 'remove') {
            meUser.friends = meUser.friends.filter(f => f.toLowerCase() !== lowerTarget);
            targetUser.friends = targetUser.friends.filter(f => f.toLowerCase() !== lowerMe);
        }
        saveUsers(users);
        sendJSON(res, 200, { ok: true, meFriends: meUser.friends, incomingCount: meUser.incomingRequests.length });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
function handleFriendStatus(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const target = (query.target || '').trim().toLowerCase();
    const users = readUsers();
    const meUser = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
    const targetUser = users.find(u => u.username.toLowerCase() === target);
    if (!meUser || !targetUser) return sendJSON(res, 404, { error: 'Пользователь не найден' });
    const isFriends = (meUser.friends || []).some(f => f.toLowerCase() === target);
    const isSent = (targetUser.incomingRequests || []).some(r => r.toLowerCase() === me.username.toLowerCase());
    const isReceived = (meUser.incomingRequests || []).some(r => r.toLowerCase() === target);
    let status = 'none';
    if (isFriends) status = 'friends';
    else if (isReceived) status = 'received';
    else if (isSent) status = 'sent';
    sendJSON(res, 200, { status });
}
function handleFriendsGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const users = readUsers();
    const user = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
    if (!user) return sendJSON(res, 404, { error: 'Пользователь не найден' });
    const friendNames = Array.isArray(user.friends) ? user.friends : [];
    const friends = users.filter(u => friendNames.some(fn => fn.toLowerCase() === u.username.toLowerCase())).map(u => ({ username: u.username, avatar: u.avatar || '', handle: u.handle || '', birthday: u.birthday || '' }));
    const reqNames = Array.isArray(user.incomingRequests) ? user.incomingRequests : [];
    const requests = users.filter(u => reqNames.some(rn => rn.toLowerCase() === u.username.toLowerCase())).map(u => ({ username: u.username, avatar: u.avatar || '', handle: u.handle || '' }));
    sendJSON(res, 200, { friends, requests });
}

/* ========== USERS ========== */

function handleUsersList(req, res) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const safe = readUsers().map(u => ({ username: u.username, email: u.email, avatar: u.avatar || '', handle: u.handle || '', theme: u.theme || 'dark', friends: u.friends || [], lastSeen: u.lastSeen || u.createdAt, createdAt: u.createdAt }));
    sendJSON(res, 200, { users: safe });
}
function handleUserSearch(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const q = normalizeHandle(query.q || '').toLowerCase();
    const users = readUsers();
    const results = q ? users.filter(u => (u.handle || '').toLowerCase().includes(q) || u.username.toLowerCase().includes(q)) : users;
    sendJSON(res, 200, { users: results.slice(0, 20).map(u => ({ username: u.username, avatar: u.avatar || '', handle: u.handle || '' })) });
}

/* ========== POSTS ========== */

function normalizePost(p, repostedByViewer) {
    return { id: p.id, username: p.username, avatar: p.avatar || '', text: p.text || '', image: p.image || '', createdAt: p.createdAt, likes: Array.isArray(p.likes) ? p.likes : [], comments: Array.isArray(p.comments) ? p.comments : [], repostOf: p.repostOf || null, repostCount: typeof p.repostCount === 'number' ? p.repostCount : 0, repostedByViewer: !!repostedByViewer };
}
function handleFeedGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const viewer = me.username.toLowerCase();
    const allPosts = readPosts();
    const feedPosts = allPosts.filter(p => !p.repostOf);
    const viewerReposts = new Set();
    allPosts.forEach(p => { if (p.username && p.username.toLowerCase() === viewer && p.repostOf && p.repostOf.id) viewerReposts.add(p.repostOf.id); });
    const posts = feedPosts.map(p => normalizePost(p, viewerReposts.has(p.id)));
    posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    sendJSON(res, 200, { posts: posts.slice(0, FEED_LIMIT) });
}
function handlePostsGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const username = (query.username || '').trim();
    if (!username) return sendJSON(res, 400, { error: 'Не указан пользователь' });
    const allPosts = readPosts();
    const viewer = me.username.toLowerCase();
    const viewerReposts = new Set();
    allPosts.forEach(p => { if (p.username && p.username.toLowerCase() === viewer && p.repostOf && p.repostOf.id) viewerReposts.add(p.repostOf.id); });
    const posts = allPosts.map(p => normalizePost(p, viewerReposts.has(p.id) || (p.repostOf && viewerReposts.has(p.repostOf.id))));
    const filtered = posts.filter(p => p.username.toLowerCase() === username.toLowerCase());
    filtered.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    sendJSON(res, 200, { posts: filtered.slice(0, POSTS_PER_WALL) });
}
async function handlePostsCreate(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const text = (data.text || '').trim();
        const image = typeof data.image === 'string' ? data.image : '';
        if (!text && !image) return sendJSON(res, 400, { error: 'Пустой пост' });
        const author = readUsers().find(u => u.username.toLowerCase() === me.username.toLowerCase());
        if (!author) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        const post = { id: makeId(), username: author.username, avatar: author.avatar || '', text, image, createdAt: new Date().toISOString(), likes: [], comments: [], repostOf: null, repostCount: 0 };
        const posts = readPosts();
        posts.push(post);
        savePosts(posts.length > 3000 ? posts.slice(-3000) : posts);
        sendJSON(res, 201, { post: normalizePost(post) });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handlePostLike(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const id = (data.id || '').trim();
        const username = me.username;
        const posts = readPosts();
        const idx = posts.findIndex(p => p.id === id);
        if (idx === -1) return sendJSON(res, 404, { error: 'Пост не найден' });
        if (!Array.isArray(posts[idx].likes)) posts[idx].likes = [];
        const lower = username.toLowerCase();
        const uIdx = posts[idx].likes.findIndex(u => u.toLowerCase() === lower);
        if (uIdx === -1) posts[idx].likes.push(username); else posts[idx].likes.splice(uIdx, 1);
        savePosts(posts);
        sendJSON(res, 200, { likes: posts[idx].likes, liked: uIdx === -1 });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handlePostComment(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const id = (data.id || '').trim();
        const text = (data.text || '').trim();
        const author = readUsers().find(u => u.username.toLowerCase() === me.username.toLowerCase());
        if (!author) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        const posts = readPosts();
        const idx = posts.findIndex(p => p.id === id);
        if (idx === -1) return sendJSON(res, 404, { error: 'Пост не найден' });
        if (!Array.isArray(posts[idx].comments)) posts[idx].comments = [];
        const comment = { id: makeId(), username: author.username, avatar: author.avatar || '', text, createdAt: new Date().toISOString() };
        posts[idx].comments.push(comment);
        savePosts(posts);
        sendJSON(res, 201, { comment, comments: posts[idx].comments });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
function handleCommentsGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const post = readPosts().find(p => p.id === (query.id || '').trim());
    if (!post) return sendJSON(res, 404, { error: 'Пост не найден' });
    sendJSON(res, 200, { comments: Array.isArray(post.comments) ? post.comments : [] });
}
async function handlePostRepost(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const id = (data.id || '').trim();
        const author = readUsers().find(u => u.username.toLowerCase() === me.username.toLowerCase());
        if (!author) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        const posts = readPosts();
        const target = posts.find(p => p.id === id);
        if (!target) return sendJSON(res, 404, { error: 'Пост не найден' });
        const originalId = target.repostOf && target.repostOf.id ? target.repostOf.id : target.id;
        const original = posts.find(p => p.id === originalId);
        if (!original) return sendJSON(res, 404, { error: 'Оригинал не найден' });
        let removed = 0;
        const kept = [];
        posts.forEach(p => {
            if (p.repostOf && p.repostOf.id === originalId && p.username && p.username.toLowerCase() === author.username.toLowerCase()) removed++;
            else kept.push(p);
        });
        if (removed > 0) {
            original.repostCount = Math.max(0, (original.repostCount || 0) - removed);
            savePosts(kept);
            return sendJSON(res, 200, { reposted: false, repostCount: original.repostCount });
        }
        const repost = { id: makeId(), username: author.username, avatar: author.avatar || '', text: '', image: '', createdAt: new Date().toISOString(), likes: [], comments: [], repostOf: { id: original.id, username: original.username, avatar: original.avatar || '', text: original.text || '', image: original.image || '', createdAt: original.createdAt }, repostCount: 0 };
        original.repostCount = (original.repostCount || 0) + 1;
        kept.push(repost);
        savePosts(kept);
        sendJSON(res, 201, { reposted: true, post: normalizePost(repost, true), repostCount: original.repostCount });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handlePostDelete(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const postId = (data.postId || '').trim();
        if (!postId) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const posts = readPosts();
        const idx = posts.findIndex(p => p.id === postId);
        if (idx === -1) return sendJSON(res, 404, { error: 'Пост не найден' });
        if (!posts[idx].username || posts[idx].username.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Можно удалять только свои посты' });
        const removed = posts[idx];
        if (removed.repostOf && removed.repostOf.id) {
            const origIdx = posts.findIndex(p => p.id === removed.repostOf.id);
            if (origIdx !== -1 && typeof posts[origIdx].repostCount === 'number') {
                posts[origIdx].repostCount = Math.max(0, posts[origIdx].repostCount - 1);
            }
        }
        posts.splice(idx, 1);
        savePosts(posts);
        sendJSON(res, 200, { ok: true });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleCommentDelete(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const postId = (data.postId || '').trim();
        const commentId = (data.commentId || '').trim();
        if (!postId || !commentId) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const posts = readPosts();
        const p = posts.find(x => x.id === postId);
        if (!p) return sendJSON(res, 404, { error: 'Пост не найден' });
        if (!Array.isArray(p.comments)) return sendJSON(res, 404, { error: 'Комментарий не найден' });
        const cIdx = p.comments.findIndex(c => c.id === commentId);
        if (cIdx === -1) return sendJSON(res, 404, { error: 'Комментарий не найден' });
        if (!p.comments[cIdx].username || p.comments[cIdx].username.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Можно удалять только свои комментарии' });
        p.comments.splice(cIdx, 1);
        savePosts(posts);
        sendJSON(res, 200, { ok: true });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

/* ========== CHANNELS ========== */

function channelPublic(c, viewer) {
    const isSub = viewer ? (c.members || []).some(m => m.toLowerCase() === viewer.toLowerCase()) : false;
    return { id: c.id, username: c.username, name: c.name, description: c.description || '', avatar: c.avatar || '', owner: c.owner, createdAt: c.createdAt, members: Array.isArray(c.members) ? c.members.length : 0, isSubscribed: isSub };
}
async function handleChannelCreate(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const name = (data.name || '').trim();
        const username = normalizeHandle(data.username || '');
        if (!name || !username) return sendJSON(res, 400, { error: 'Заполните название и юзернейм канала' });
        if (!HANDLE_RE.test(username)) return sendJSON(res, 400, { error: 'Юзернейм: 3-20 символов' });
        const channels = readChannels();
        if (channels.some(c => c.username.toLowerCase() === username.toLowerCase())) return sendJSON(res, 409, { error: 'Юзернейм канала занят' });
        const channel = { id: makeId(), username, name, description: (data.description || '').trim(), avatar: data.avatar || '', owner: me.username, members: [me.username], messages: [], pinnedMessageId: null, createdAt: new Date().toISOString() };
        channels.push(channel); saveChannels(channels);
        sendJSON(res, 201, { channel: channelPublic(channel, me.username) });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleChannelUpdate(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const originalUsername = normalizeHandle(data.originalUsername || '');
        const newName = (data.name || '').trim();
        const newUsername = normalizeHandle(data.username || '');
        const description = (data.description || '').trim();
        const avatar = typeof data.avatar === 'string' ? data.avatar : null;
        if (!originalUsername || !newName || !newUsername) return sendJSON(res, 400, { error: 'Заполните все поля' });
        if (!HANDLE_RE.test(newUsername)) return sendJSON(res, 400, { error: 'Юзернейм: 3-20 символов' });
        const channels = readChannels();
        const ch = channels.find(c => c.username.toLowerCase() === originalUsername.toLowerCase());
        if (!ch) return sendJSON(res, 404, { error: 'Канал не найден' });
        if (ch.owner.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Только владелец' });
        if (newUsername.toLowerCase() !== originalUsername.toLowerCase() && channels.some(c => c.username.toLowerCase() === newUsername.toLowerCase())) return sendJSON(res, 409, { error: 'Занят' });
        ch.name = newName; ch.username = newUsername; ch.description = description;
        if (avatar !== null) ch.avatar = avatar;
        saveChannels(channels);
        sendJSON(res, 200, { channel: channelPublic(ch, me.username) });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleChannelSubscribe(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const channelUsername = normalizeHandle(data.channel || '');
        if (!channelUsername) return sendJSON(res, 400, { error: 'Не хватает данных' });
        const channels = readChannels();
        const ch = channels.find(c => c.username.toLowerCase() === channelUsername.toLowerCase());
        if (!ch) return sendJSON(res, 404, { error: 'Канал не найден' });
        if (!Array.isArray(ch.members)) ch.members = [];
        const lowerUser = me.username.toLowerCase();
        const idx = ch.members.findIndex(m => m.toLowerCase() === lowerUser);
        let subscribed;
        if (idx === -1) { ch.members.push(me.username); subscribed = true; } else { ch.members.splice(idx, 1); subscribed = false; }
        saveChannels(channels);
        sendJSON(res, 200, { subscribed, memberCount: ch.members.length });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
function handleChannelGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const c = readChannels().find(x => x.username.toLowerCase() === normalizeHandle(query.username || '').toLowerCase());
    if (!c) return sendJSON(res, 404, { error: 'Канал не найден' });
    sendJSON(res, 200, { channel: channelPublic(c, me.username) });
}
function handleChannelSearch(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const q = normalizeHandle(query.q || '').toLowerCase();
    const channels = readChannels();
    const found = q ? channels.filter(c => c.username.toLowerCase().includes(q) || c.name.toLowerCase().includes(q)) : channels;
    sendJSON(res, 200, { channels: found.slice(0, 20).map(c => channelPublic(c, me.username)) });
}
function handleChannelMessagesGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const c = readChannels().find(x => x.username.toLowerCase() === normalizeHandle(query.username || '').toLowerCase());
    if (!c) return sendJSON(res, 404, { error: 'Канал не найден' });
    sendJSON(res, 200, { messages: (c.messages || []).slice(-300), pinnedMessageId: c.pinnedMessageId || null });
}
async function handleChannelMessageCreate(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const channels = readChannels();
        const c = channels.find(x => x.username.toLowerCase() === normalizeHandle(data.channel || '').toLowerCase());
        if (!c) return sendJSON(res, 404, { error: 'Канал не найден' });
        if (c.owner.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Только владелец' });
        const msg = { id: makeId(), from: c.name, channelUsername: c.username, channelAvatar: c.avatar || '', text: (data.text || '').trim(), reactions: { like: [], fire: [], demon: [] }, createdAt: new Date().toISOString() };
        if (!Array.isArray(c.messages)) c.messages = [];
        c.messages.push(msg);
        saveChannels(channels);
        sendJSON(res, 201, { message: msg });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleChannelMessageReaction(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const channelUsername = normalizeHandle(data.channel || '');
        const messageId = (data.messageId || '').trim();
        const reactionType = (data.type || '').trim();
        if (!['like', 'fire', 'demon'].includes(reactionType)) return sendJSON(res, 400, { error: 'Неизвестный тип реакции' });
        const channels = readChannels();
        const c = channels.find(x => x.username.toLowerCase() === channelUsername.toLowerCase());
        if (!c) return sendJSON(res, 404, { error: 'Канал не найден' });
        const msg = (c.messages || []).find(m => m.id === messageId);
        if (!msg) return sendJSON(res, 404, { error: 'Сообщение не найдено' });
        if (!msg.reactions) msg.reactions = { like: [], fire: [], demon: [] };
        if (!Array.isArray(msg.reactions[reactionType])) msg.reactions[reactionType] = [];
        const lowerUser = me.username.toLowerCase();
        const idx = msg.reactions[reactionType].findIndex(u => u.toLowerCase() === lowerUser);
        if (idx === -1) msg.reactions[reactionType].push(me.username);
        else msg.reactions[reactionType].splice(idx, 1);
        saveChannels(channels);
        sendJSON(res, 200, { reactions: msg.reactions });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleChannelPin(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const channelUsername = normalizeHandle(data.channel || '');
        const messageId = (data.messageId || '').trim();
        const pinned = !!data.pinned;
        if (!channelUsername) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const channels = readChannels();
        const c = channels.find(x => x.username.toLowerCase() === channelUsername.toLowerCase());
        if (!c) return sendJSON(res, 404, { error: 'Канал не найден' });
        if (c.owner.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Только владелец канала может закреплять' });
        if (pinned) {
            if (!messageId) return sendJSON(res, 400, { error: 'Не указано сообщение' });
            const msg = (c.messages || []).find(m => m.id === messageId);
            if (!msg) return sendJSON(res, 404, { error: 'Сообщение не найдено' });
            c.pinnedMessageId = messageId;
        } else {
            c.pinnedMessageId = null;
        }
        saveChannels(channels);
        sendJSON(res, 200, { ok: true, pinnedMessageId: c.pinnedMessageId });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleChannelMessageDelete(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const channelUsername = normalizeHandle(data.channel || '');
        const messageId = (data.messageId || '').trim();
        if (!channelUsername || !messageId) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const channels = readChannels();
        const c = channels.find(x => x.username.toLowerCase() === channelUsername.toLowerCase());
        if (!c) return sendJSON(res, 404, { error: 'Канал не найден' });
        if (c.owner.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Только владелец канала может удалять сообщения' });
        const before = (c.messages || []).length;
        c.messages = (c.messages || []).filter(m => m.id !== messageId);
        if (c.messages.length === before) return sendJSON(res, 404, { error: 'Сообщение не найдено' });
        if (c.pinnedMessageId === messageId) c.pinnedMessageId = null;
        saveChannels(channels);
        sendJSON(res, 200, { ok: true });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

/* ========== CHATS ========== */

async function handleChatCreate(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const name = (data.name || '').trim();
        let members = Array.isArray(data.members) ? data.members : [];
        if (!members.some(x => x.toLowerCase() === me.username.toLowerCase())) members.unshift(me.username);
        const chat = { id: makeId(), name, owner: me.username, members, messages: [], pinnedMessageId: null, createdAt: new Date().toISOString() };
        const chats = readChats();
        chats.push(chat);
        saveChats(chats);
        sendJSON(res, 201, { chat: { id: chat.id, name: chat.name, owner: chat.owner, members: chat.members, memberCount: chat.members.length } });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
function handleChatsGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const user = me.username.toLowerCase();
    const list = readChats().filter(c => (c.members || []).some(m => m.toLowerCase() === user)).map(c => {
        const last = c.messages && c.messages.length ? c.messages[c.messages.length - 1] : null;
        let unread = 0;
        (c.messages || []).forEach(m => {
            if (m.from.toLowerCase() === user) return;
            if (!Array.isArray(m.read)) return;
            if (!m.read.some(u => u.toLowerCase() === user)) unread++;
        });
        return { id: c.id, name: c.name, owner: c.owner, members: c.members, memberCount: c.members.length, lastText: last ? last.text : '', lastAt: last ? last.createdAt : c.createdAt, unread };
    });
    sendJSON(res, 200, { chats: list });
}
function handleChatMessagesGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const chatId = (query.id || '').trim();
    const chats = readChats();
    const chat = chats.find(x => x.id === chatId);
    if (!chat) return sendJSON(res, 404, { error: 'Чат не найден' });
    let changed = false;
    (chat.messages || []).forEach(m => {
        if (!Array.isArray(m.read)) m.read = [];
        if (m.from.toLowerCase() !== me.username.toLowerCase() && !m.read.some(u => u.toLowerCase() === me.username.toLowerCase())) {
            m.read.push(me.username);
            changed = true;
        }
    });
    if (changed) saveChats(chats);
    sendJSON(res, 200, {
        chat: { id: chat.id, name: chat.name, memberCount: chat.members.length, owner: chat.owner, pinnedMessageId: chat.pinnedMessageId || null },
        messages: (chat.messages || []).slice(-300)
    });
}
async function handleChatMessageCreate(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const chats = readChats();
        const c = chats.find(x => x.id === data.id);
        if (!c) return sendJSON(res, 404, { error: 'Чат не найден' });
        const msg = { id: makeId(), from: me.username, text: (data.text || '').trim(), read: [], createdAt: new Date().toISOString() };
        if (!Array.isArray(c.messages)) c.messages = [];
        c.messages.push(msg);
        saveChats(chats);
        sendJSON(res, 201, { message: msg });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleChatPin(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const chatId = (data.chatId || '').trim();
        const messageId = (data.messageId || '').trim();
        const pinned = !!data.pinned;
        if (!chatId) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const chats = readChats();
        const c = chats.find(x => x.id === chatId);
        if (!c) return sendJSON(res, 404, { error: 'Чат не найден' });
        if (c.owner.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Только создатель чата может закреплять' });
        if (pinned) {
            if (!messageId) return sendJSON(res, 400, { error: 'Не указано сообщение' });
            const msg = (c.messages || []).find(m => m.id === messageId);
            if (!msg) return sendJSON(res, 404, { error: 'Сообщение не найдено' });
            c.pinnedMessageId = messageId;
        } else {
            c.pinnedMessageId = null;
        }
        saveChats(chats);
        sendJSON(res, 200, { ok: true, pinnedMessageId: c.pinnedMessageId });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
async function handleChatMessageDelete(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const chatId = (data.chatId || '').trim();
        const messageId = (data.messageId || '').trim();
        if (!chatId || !messageId) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const chats = readChats();
        const c = chats.find(x => x.id === chatId);
        if (!c) return sendJSON(res, 404, { error: 'Чат не найден' });
        const msg = (c.messages || []).find(m => m.id === messageId);
        if (!msg) return sendJSON(res, 404, { error: 'Сообщение не найдено' });
        const isAuthor = msg.from && msg.from.toLowerCase() === me.username.toLowerCase();
        const isOwner = c.owner && c.owner.toLowerCase() === me.username.toLowerCase();
        if (!isAuthor && !isOwner) return sendJSON(res, 403, { error: 'Можно удалять только свои сообщения' });
        c.messages = (c.messages || []).filter(m => m.id !== messageId);
        if (c.pinnedMessageId === messageId) c.pinnedMessageId = null;
        saveChats(chats);
        sendJSON(res, 200, { ok: true });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

/* ========== DM ========== */

function handleDmGet(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const user = me.username;
    const withUser = (query.with || '').trim();
    const key = dmKey(user, withUser);
    const dms = readDms();
    let changed = false;
    dms.forEach(m => {
        if (dmKey(m.from, m.to) === key && m.to.toLowerCase() === user.toLowerCase() && m.type !== 'call') {
            if (!m.delivered) { m.delivered = true; changed = true; }
            if (!m.read) { m.read = true; changed = true; }
        }
    });
    if (changed) saveDms(dms);
    const conv = dms.filter(m => dmKey(m.from, m.to) === key);
    sendJSON(res, 200, { messages: conv.slice(-DM_HISTORY_LIMIT) });
}
async function handleDmCreate(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const toLower = (data.to || '').trim().toLowerCase();
        const users = readUsers();
        const sender = users.find(u => u.username.toLowerCase() === me.username.toLowerCase());
        const recipient = users.find(u => u.username.toLowerCase() === toLower);
        if (!sender || !recipient) return sendJSON(res, 404, { error: 'Пользователь не найден' });
        if ((sender.blocked || []).some(b => b.toLowerCase() === toLower)) return sendJSON(res, 403, { error: 'Вы заблокировали этого пользователя' });
        if ((recipient.blocked || []).some(b => b.toLowerCase() === me.username.toLowerCase())) return sendJSON(res, 403, { error: 'Пользователь заблокировал вас' });
        const isOnline = recipient.lastSeen && (Date.now() - new Date(recipient.lastSeen).getTime() < 35000);
        const message = { id: makeId(), from: sender.username, to: recipient.username, text: (data.text || '').trim(), image: typeof data.image === 'string' ? data.image : '', delivered: !!isOnline, read: false, createdAt: new Date().toISOString() };
        const dms = readDms();
        dms.push(message);
        saveDms(dms.length > 5000 ? dms.slice(-5000) : dms);
        sendJSON(res, 201, { message });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}
function handleDmConversations(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const user = me.username.toLowerCase();
    const dms = readDms();
    const users = readUsers();
    const map = {};
    dms.forEach(m => {
        const fromLower = (m.from || '').toLowerCase();
        const toLower = (m.to || '').toLowerCase();
        if (fromLower !== user && toLower !== user) return;
        const partnerName = fromLower === user ? m.to : m.from;
        const partnerLower = partnerName.toLowerCase();
        if (!map[partnerLower]) map[partnerLower] = { partnerUsername: partnerName, lastMessage: m, unread: 0 };
        if (new Date(m.createdAt) > new Date(map[partnerLower].lastMessage.createdAt)) map[partnerLower].lastMessage = m;
        if (toLower === user && !m.read && m.type !== 'call') map[partnerLower].unread++;
    });
    const callLabels = { outgoing: '📞 Исходящий', incoming: '📞 Входящий', missed: '📵 Пропущенный', cancelled: '❌ Отменён', declined: '📵 Отклонён' };
    const list = Object.keys(map).map(k => {
        const partner = users.find(u => u.username.toLowerCase() === k);
        const lastMsg = map[k].lastMessage;
        let previewText = lastMsg.text || '';
        if (lastMsg.forwardedFrom) previewText = '↪ ' + previewText;
        if (lastMsg.type === 'call') {
            let label = callLabels[lastMsg.callType] || '📞 Звонок';
            let durStr = '';
            if (lastMsg.duration > 0) {
                const mm = Math.floor(lastMsg.duration / 60);
                const ss = lastMsg.duration % 60;
                durStr = ' ' + (mm < 10 ? '0' : '') + mm + ':' + (ss < 10 ? '0' : '') + ss;
            }
            previewText = label + durStr;
        }
        if (!previewText && lastMsg.image) previewText = '📷 Фото';
        return { username: partner ? partner.username : map[k].partnerUsername, avatar: partner ? partner.avatar : '', handle: partner ? partner.handle : '', lastText: previewText, lastFrom: lastMsg.from, lastAt: lastMsg.createdAt, unread: map[k].unread };
    }).sort((a, b) => new Date(b.lastAt) - new Date(a.lastAt));
    sendJSON(res, 200, { conversations: list });
}
function handleDmUnreadCount(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const user = me.username.toLowerCase();
    const count = readDms().filter(m => m.to && m.to.toLowerCase() === user && !m.read && m.type !== 'call').length;
    sendJSON(res, 200, { count });
}
async function handleDmDelete(req, res) {
    try {
        const me = authUser(req);
        if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
        const data = await readBody(req);
        const messageId = (data.messageId || '').trim();
        if (!messageId) return sendJSON(res, 400, { error: 'Недостаточно данных' });
        const dms = readDms();
        const idx = dms.findIndex(m => m.id === messageId);
        if (idx === -1) return sendJSON(res, 404, { error: 'Сообщение не найдено' });
        if (!dms[idx].from || dms[idx].from.toLowerCase() !== me.username.toLowerCase()) return sendJSON(res, 403, { error: 'Можно удалять только свои сообщения' });
        dms.splice(idx, 1);
        saveDms(dms);
        sendJSON(res, 200, { ok: true });
    } catch (e) { sendJSON(res, 500, { error: 'Ошибка сервера' }); }
}

/* ========== COMMUNICATION ========== */

function handleCommunication(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const user = me.username.toLowerCase();
    const channelsList = readChannels()
        .filter(c => {
            if (c.owner.toLowerCase() === user) return true;
            if ((c.members || []).some(m => m.toLowerCase() === user)) return true;
            return false;
        })
        .map(c => {
            const last = c.messages && c.messages.length ? c.messages[c.messages.length - 1] : null;
            const isOwner = c.owner.toLowerCase() === user;
            return { type: 'channel', id: c.id, username: c.username, name: c.name, avatar: c.avatar || '', members: Array.isArray(c.members) ? c.members.length : 0, isOwner, lastText: last ? last.text : '', lastAt: last ? last.createdAt : c.createdAt, unread: 0 };
        });
    const chatsList = readChats()
        .filter(c => (c.members || []).some(m => m.toLowerCase() === user))
        .map(c => {
            const last = c.messages && c.messages.length ? c.messages[c.messages.length - 1] : null;
            let unread = 0;
            (c.messages || []).forEach(m => {
                if (m.from.toLowerCase() === user) return;
                if (!Array.isArray(m.read)) return;
                if (!m.read.some(u => u.toLowerCase() === user)) unread++;
            });
            return { type: 'chat', id: c.id, name: c.name, avatar: '', members: (c.members || []).length, isOwner: c.owner.toLowerCase() === user, lastText: last ? (last.from + ': ' + last.text) : '', lastAt: last ? last.createdAt : c.createdAt, unread };
        });
    const all = channelsList.concat(chatsList).sort((a, b) => new Date(b.lastAt) - new Date(a.lastAt));
    sendJSON(res, 200, { items: all });
}
function handleCommunicationUnreadCount(req, res, query) {
    const me = authUser(req);
    if (!me) return sendJSON(res, 401, { error: 'Не авторизован' });
    const user = me.username.toLowerCase();
    let count = 0;
    readChats().forEach(c => {
        if (!(c.members || []).some(m => m.toLowerCase() === user)) return;
        (c.messages || []).forEach(m => {
            if (m.from.toLowerCase() === user) return;
            if (!Array.isArray(m.read)) return;
            if (!m.read.some(u => u.toLowerCase() === user)) count++;
        });
    });
    sendJSON(res, 200, { count });
}

/* ========== SERVER ========== */

const server = http.createServer(function (req, res) {
    const parsedUrl = parseUrl(req.url, true);
    const url = parsedUrl.pathname;
    const query = parsedUrl.query;

    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
            'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS'
        });
        res.end();
        return;
    }

    // Auth
    if (url === '/api/register' && req.method === 'POST') return handleRegister(req, res);
    if (url === '/api/login' && req.method === 'POST') return handleLogin(req, res);
    if (url === '/api/logout' && req.method === 'POST') return handleLogout(req, res);
    if (url === '/api/auth/session' && req.method === 'GET') return handleSession(req, res);

    // Users
    if (url === '/api/users' && req.method === 'GET') return handleUsersList(req, res);
    if (url === '/api/update-profile' && req.method === 'POST') return handleUpdateProfile(req, res);
    if (url === '/api/users/search' && req.method === 'GET') return handleUserSearch(req, res, query);
    if (url === '/api/user/heartbeat' && req.method === 'POST') return handleHeartbeat(req, res);
    if (url === '/api/user/status' && req.method === 'GET') return handleUserStatus(req, res, query);

    // Calls
    if (url === '/api/call/signal' && req.method === 'POST') return handleCallSignalSend(req, res);
    if (url === '/api/call/poll' && req.method === 'GET') return handleCallSignalPoll(req, res, query);
    if (url === '/api/call/log' && req.method === 'POST') return handleCallLog(req, res);

    // Friends
    if (url === '/api/friends/action' && req.method === 'POST') return handleFriendAction(req, res);
    if (url === '/api/friends/status' && req.method === 'GET') return handleFriendStatus(req, res, query);
    if (url === '/api/friends' && req.method === 'GET') return handleFriendsGet(req, res, query);

    // Block
    if (url === '/api/users/block' && req.method === 'POST') return handleBlockToggle(req, res);
    if (url === '/api/users/blocked' && req.method === 'GET') return handleBlockedList(req, res, query);
    if (url === '/api/users/block-status' && req.method === 'GET') return handleBlockStatus(req, res, query);

    // Channels
    if (url === '/api/channels' && req.method === 'GET') return handleChannelGet(req, res, query);
    if (url === '/api/channels' && req.method === 'POST') return handleChannelCreate(req, res);
    if (url === '/api/channels/update' && req.method === 'POST') return handleChannelUpdate(req, res);
    if (url === '/api/channels/subscribe' && req.method === 'POST') return handleChannelSubscribe(req, res);
    if (url === '/api/channels/search' && req.method === 'GET') return handleChannelSearch(req, res, query);
    if (url === '/api/channels/messages' && req.method === 'GET') return handleChannelMessagesGet(req, res, query);
    if (url === '/api/channels/message' && req.method === 'POST') return handleChannelMessageCreate(req, res);
    if (url === '/api/channels/message/reaction' && req.method === 'POST') return handleChannelMessageReaction(req, res);
    if (url === '/api/channels/message/delete' && req.method === 'POST') return handleChannelMessageDelete(req, res);
    if (url === '/api/channels/pin' && req.method === 'POST') return handleChannelPin(req, res);

    // Chats
    if (url === '/api/chats' && req.method === 'GET') return handleChatsGet(req, res, query);
    if (url === '/api/chats' && req.method === 'POST') return handleChatCreate(req, res);
    if (url === '/api/chats/messages' && req.method === 'GET') return handleChatMessagesGet(req, res, query);
    if (url === '/api/chats/message' && req.method === 'POST') return handleChatMessageCreate(req, res);
    if (url === '/api/chats/message/delete' && req.method === 'POST') return handleChatMessageDelete(req, res);
    if (url === '/api/chats/pin' && req.method === 'POST') return handleChatPin(req, res);

    // Posts
    if (url === '/api/posts/feed' && req.method === 'GET') return handleFeedGet(req, res, query);
    if (url === '/api/posts' && req.method === 'GET') return handlePostsGet(req, res, query);
    if (url === '/api/posts' && req.method === 'POST') return handlePostsCreate(req, res);
    if (url === '/api/posts/like' && req.method === 'POST') return handlePostLike(req, res);
    if (url === '/api/posts/comment' && req.method === 'POST') return handlePostComment(req, res);
    if (url === '/api/posts/comments' && req.method === 'GET') return handleCommentsGet(req, res, query);
    if (url === '/api/posts/repost' && req.method === 'POST') return handlePostRepost(req, res);
    if (url === '/api/posts/delete' && req.method === 'POST') return handlePostDelete(req, res);
    if (url === '/api/posts/comment/delete' && req.method === 'POST') return handleCommentDelete(req, res);

    // DM
    if (url === '/api/dm' && req.method === 'GET') return handleDmGet(req, res, query);
    if (url === '/api/dm' && req.method === 'POST') return handleDmCreate(req, res);
    if (url === '/api/dm/forward' && req.method === 'POST') return handleForward(req, res);
    if (url === '/api/dm/delete' && req.method === 'POST') return handleDmDelete(req, res);
    if (url === '/api/dm/conversations' && req.method === 'GET') return handleDmConversations(req, res, query);
    if (url === '/api/dm/unread-count' && req.method === 'GET') return handleDmUnreadCount(req, res, query);

    // Communication
    if (url === '/api/communication' && req.method === 'GET') return handleCommunication(req, res, query);
    if (url === '/api/communication/unread-count' && req.method === 'GET') return handleCommunicationUnreadCount(req, res, query);

    if (url === '/' || url === '/index.html') {
        try {
            const html = fs.readFileSync(HTML_FILE, 'utf8');
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(html);
        } catch (e) {
            res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('index.html не найден рядом с server.js');
        }
        return;
    }

    sendJSON(res, 404, { error: 'Не найдено' });
});

server.listen(PORT, '0.0.0.0', function () {
    console.log('');
    console.log('🔥 Сервер Hot успешно запущен!');
    console.log('👉 Открой в браузере: http://localhost:' + PORT);
    console.log('');
});
