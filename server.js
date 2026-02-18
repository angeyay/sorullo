const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["https://fonts.gstatic.com"],
            connectSrc: ["'self'"],
            imgSrc: ["'self'", "data:"],
        }
    },
    referrerPolicy: { policy: 'no-referrer' }
}));

// Rate limiting
// Note: if running behind a reverse proxy, add: app.set('trust proxy', 1)
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 200,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
});

const writeLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' }
});

app.use('/api', apiLimiter);

// Middleware
app.use(express.json({ limit: '50kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const db = new Database(path.join(__dirname, 'sorullo.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
    CREATE TABLE IF NOT EXISTS events (
        id TEXT PRIMARY KEY,
        host_key TEXT NOT NULL,
        data TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now')),
        updated_at TEXT DEFAULT (datetime('now'))
    )
`);

// Input limits
const LIMITS = {
    name: 200,
    place: 500,
    pin: 2000,
    description: 5000,
    itemName: 200,
    claimantName: 100,
    notes: 500,
    maxItems: 100,
    maxCustomItems: 50,
    maxClaimantsPerItem: 20,
};

// Helpers
function generateId() {
    return crypto.randomBytes(8).toString('hex'); // 64-bit URL-safe ID
}

function generateSecret() {
    return crypto.randomBytes(16).toString('hex'); // 128-bit secret for host keys
}

function getEvent(id) {
    const row = db.prepare('SELECT * FROM events WHERE id = ?').get(id);
    if (!row) return null;
    let event;
    try {
        event = JSON.parse(row.data);
    } catch {
        return null;
    }
    event.id = row.id;
    event.hostKey = row.host_key;
    return event;
}

function saveEvent(event) {
    const data = JSON.stringify({
        name: event.name,
        date: event.date,
        time: event.time,
        place: event.place,
        pin: event.pin,
        description: event.description,
        items: event.items || [],
        customItems: event.customItems || []
    });
    db.prepare(`
        INSERT INTO events (id, host_key, data, updated_at)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at
    `).run(event.id, event.hostKey, data);
}

function stripHostKey(event) {
    const { hostKey, ...rest } = event;
    return rest;
}

function findItem(event, itemId, isCustom) {
    const list = isCustom ? event.customItems : event.items;
    return list ? list.find(i => i.id === itemId) : null;
}

// =====================
// API ROUTES
// =====================

// Create event
app.post('/api/events', writeLimiter, (req, res) => {
    const { name, date, time, place, pin, description, items } = req.body;

    if (!name || !date || !time || !place) {
        return res.status(400).json({ error: 'Missing required fields: name, date, time, place' });
    }
    if (typeof name !== 'string' || name.trim().length === 0 || name.trim().length > LIMITS.name) {
        return res.status(400).json({ error: `Event name must be 1–${LIMITS.name} characters` });
    }
    if (typeof place !== 'string' || place.trim().length === 0 || place.trim().length > LIMITS.place) {
        return res.status(400).json({ error: `Place must be 1–${LIMITS.place} characters` });
    }
    if (pin && (typeof pin !== 'string' || pin.length > LIMITS.pin)) {
        return res.status(400).json({ error: `Pin URL must be under ${LIMITS.pin} characters` });
    }
    if (description && (typeof description !== 'string' || description.length > LIMITS.description)) {
        return res.status(400).json({ error: `Description must be under ${LIMITS.description} characters` });
    }
    if (items && (!Array.isArray(items) || items.length > LIMITS.maxItems)) {
        return res.status(400).json({ error: `Cannot have more than ${LIMITS.maxItems} items` });
    }

    const event = {
        id: generateId(),
        hostKey: generateSecret(),
        name: name.trim(),
        date,
        time,
        place: place.trim(),
        pin: pin || '',
        description: description || '',
        items: (items || [])
            .map(item => ({
                id: generateId(),
                name: (item.name || '').toString().trim().slice(0, LIMITS.itemName),
                claimants: []
            }))
            .filter(item => item.name),
        customItems: []
    };

    saveEvent(event);
    res.status(201).json({ id: event.id, hostKey: event.hostKey });
});

// Get event
app.get('/api/events/:id', (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const hostKey = req.query.hostKey;
    if (hostKey && hostKey === event.hostKey) {
        return res.json(event);
    }

    res.json(stripHostKey(event));
});

// Update event details (host only)
app.put('/api/events/:id', writeLimiter, (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const hostKey = req.body.hostKey;
    if (!hostKey || hostKey !== event.hostKey) {
        return res.status(403).json({ error: 'Invalid host key' });
    }

    if (req.body.name !== undefined) {
        if (typeof req.body.name !== 'string' || req.body.name.trim().length === 0 || req.body.name.trim().length > LIMITS.name) {
            return res.status(400).json({ error: `Event name must be 1–${LIMITS.name} characters` });
        }
        event.name = req.body.name.trim();
    }
    if (req.body.date !== undefined) event.date = req.body.date;
    if (req.body.time !== undefined) event.time = req.body.time;
    if (req.body.place !== undefined) {
        if (typeof req.body.place !== 'string' || req.body.place.trim().length === 0 || req.body.place.trim().length > LIMITS.place) {
            return res.status(400).json({ error: `Place must be 1–${LIMITS.place} characters` });
        }
        event.place = req.body.place.trim();
    }
    if (req.body.pin !== undefined) {
        if (req.body.pin && (typeof req.body.pin !== 'string' || req.body.pin.length > LIMITS.pin)) {
            return res.status(400).json({ error: `Pin URL must be under ${LIMITS.pin} characters` });
        }
        event.pin = req.body.pin;
    }
    if (req.body.description !== undefined) {
        if (req.body.description && (typeof req.body.description !== 'string' || req.body.description.length > LIMITS.description)) {
            return res.status(400).json({ error: `Description must be under ${LIMITS.description} characters` });
        }
        event.description = req.body.description;
    }

    saveEvent(event);
    res.json(event);
});

// Add item (host only)
app.post('/api/events/:id/items', writeLimiter, (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const hostKey = req.body.hostKey;
    if (!hostKey || hostKey !== event.hostKey) {
        return res.status(403).json({ error: 'Invalid host key' });
    }

    const { name } = req.body;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({ error: 'Item name is required' });
    }
    if (name.trim().length > LIMITS.itemName) {
        return res.status(400).json({ error: `Item name must be under ${LIMITS.itemName} characters` });
    }
    if ((event.items || []).length >= LIMITS.maxItems) {
        return res.status(400).json({ error: `Cannot have more than ${LIMITS.maxItems} items` });
    }

    const item = { id: generateId(), name: name.trim(), claimants: [] };
    event.items.push(item);
    saveEvent(event);
    res.status(201).json(event);
});

// Remove item (host only)
app.delete('/api/events/:id/items/:itemId', writeLimiter, (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const hostKey = req.query.hostKey;
    if (!hostKey || hostKey !== event.hostKey) {
        return res.status(403).json({ error: 'Invalid host key' });
    }

    const isCustom = req.query.isCustom === 'true';
    if (isCustom) {
        event.customItems = (event.customItems || []).filter(i => i.id !== req.params.itemId);
    } else {
        event.items = event.items.filter(i => i.id !== req.params.itemId);
    }

    saveEvent(event);
    res.json(event);
});

// Remove claimant from item (host only)
app.delete('/api/events/:id/items/:itemId/claimants/:name', writeLimiter, (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const hostKey = req.query.hostKey;
    if (!hostKey || hostKey !== event.hostKey) {
        return res.status(403).json({ error: 'Invalid host key' });
    }

    const isCustom = req.query.isCustom === 'true';
    const item = findItem(event, req.params.itemId, isCustom);

    if (item && item.claimants) {
        item.claimants = item.claimants.filter(c => c.name !== decodeURIComponent(req.params.name));
        saveEvent(event);
    }

    res.json(event);
});

// Claim item (guest)
app.post('/api/events/:id/items/:itemId/claim', writeLimiter, (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const { name, notes, isCustom } = req.body;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({ error: 'Name is required' });
    }
    if (name.trim().length > LIMITS.claimantName) {
        return res.status(400).json({ error: `Name must be under ${LIMITS.claimantName} characters` });
    }
    if (notes && (typeof notes !== 'string' || notes.length > LIMITS.notes)) {
        return res.status(400).json({ error: `Notes must be under ${LIMITS.notes} characters` });
    }

    const item = findItem(event, req.params.itemId, isCustom);
    if (!item) {
        return res.status(404).json({ error: 'Item not found' });
    }

    item.claimants = item.claimants || [];
    const trimmedName = name.trim();

    if (item.claimants.some(c => c.name === trimmedName)) {
        return res.status(409).json({ error: 'This name has already claimed this item' });
    }
    if (item.claimants.length >= LIMITS.maxClaimantsPerItem) {
        return res.status(400).json({ error: 'Maximum claimants reached for this item' });
    }

    item.claimants.push({ name: trimmedName, notes: notes ? notes.trim() : '' });
    saveEvent(event);
    res.json(stripHostKey(event));
});

// Unclaim item (guest)
app.post('/api/events/:id/items/:itemId/unclaim', writeLimiter, (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const { name, isCustom } = req.body;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({ error: 'Name is required' });
    }

    const item = findItem(event, req.params.itemId, isCustom);
    if (item && item.claimants) {
        const idx = item.claimants.findIndex(c => c.name === name.trim());
        if (idx !== -1) {
            item.claimants.splice(idx, 1);
            saveEvent(event);
        }
    }

    res.json(stripHostKey(event));
});

// Add custom item (guest)
app.post('/api/events/:id/custom-items', writeLimiter, (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const { name, claimedBy, notes } = req.body;
    if (!name || typeof name !== 'string' || name.trim().length === 0) {
        return res.status(400).json({ error: 'Item name is required' });
    }
    if (!claimedBy || typeof claimedBy !== 'string' || claimedBy.trim().length === 0) {
        return res.status(400).json({ error: 'Your name is required' });
    }
    if (name.trim().length > LIMITS.itemName) {
        return res.status(400).json({ error: `Item name must be under ${LIMITS.itemName} characters` });
    }
    if (claimedBy.trim().length > LIMITS.claimantName) {
        return res.status(400).json({ error: `Name must be under ${LIMITS.claimantName} characters` });
    }
    if (notes && (typeof notes !== 'string' || notes.length > LIMITS.notes)) {
        return res.status(400).json({ error: `Notes must be under ${LIMITS.notes} characters` });
    }

    event.customItems = event.customItems || [];
    if (event.customItems.length >= LIMITS.maxCustomItems) {
        return res.status(400).json({ error: `Cannot have more than ${LIMITS.maxCustomItems} custom items` });
    }

    const item = {
        id: generateId(),
        name: name.trim(),
        claimants: [{ name: claimedBy.trim(), notes: notes ? notes.trim() : '' }],
        isCustom: true
    };
    event.customItems.push(item);
    saveEvent(event);
    res.json(stripHostKey(event));
});

// SPA fallback — serve index.html for all non-API routes
app.get('{*path}', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Sorullo server running on http://localhost:${PORT}`);
});
