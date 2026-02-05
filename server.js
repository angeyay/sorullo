const express = require('express');
const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
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

// Helpers
function generateId() {
    return crypto.randomBytes(6).toString('hex');
}

function getEvent(id) {
    const row = db.prepare('SELECT * FROM events WHERE id = ?').get(id);
    if (!row) return null;
    const event = JSON.parse(row.data);
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
app.post('/api/events', (req, res) => {
    const { name, date, time, place, pin, description, items } = req.body;

    if (!name || !date || !time || !place) {
        return res.status(400).json({ error: 'Missing required fields: name, date, time, place' });
    }

    const event = {
        id: generateId(),
        hostKey: generateId(),
        name,
        date,
        time,
        place,
        pin: pin || '',
        description: description || '',
        items: (items || []).map(item => ({
            id: item.id || generateId(),
            name: item.name,
            claimants: []
        })),
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
app.put('/api/events/:id', (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const hostKey = req.body.hostKey;
    if (!hostKey || hostKey !== event.hostKey) {
        return res.status(403).json({ error: 'Invalid host key' });
    }

    if (req.body.name !== undefined) event.name = req.body.name;
    if (req.body.date !== undefined) event.date = req.body.date;
    if (req.body.time !== undefined) event.time = req.body.time;
    if (req.body.place !== undefined) event.place = req.body.place;
    if (req.body.pin !== undefined) event.pin = req.body.pin;
    if (req.body.description !== undefined) event.description = req.body.description;

    saveEvent(event);
    res.json(event);
});

// Add item (host only)
app.post('/api/events/:id/items', (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const hostKey = req.body.hostKey;
    if (!hostKey || hostKey !== event.hostKey) {
        return res.status(403).json({ error: 'Invalid host key' });
    }

    const { name } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Item name is required' });
    }

    const item = { id: generateId(), name, claimants: [] };
    event.items.push(item);
    saveEvent(event);
    res.status(201).json(event);
});

// Remove item (host only)
app.delete('/api/events/:id/items/:itemId', (req, res) => {
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
app.delete('/api/events/:id/items/:itemId/claimants/:name', (req, res) => {
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
app.post('/api/events/:id/items/:itemId/claim', (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const { name, notes, isCustom } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Name is required' });
    }

    const item = findItem(event, req.params.itemId, isCustom);
    if (!item) {
        return res.status(404).json({ error: 'Item not found' });
    }

    item.claimants = item.claimants || [];
    item.claimants.push({ name, notes: notes || '' });
    saveEvent(event);
    res.json(stripHostKey(event));
});

// Unclaim item (guest)
app.post('/api/events/:id/items/:itemId/unclaim', (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const { name, isCustom } = req.body;
    if (!name) {
        return res.status(400).json({ error: 'Name is required' });
    }

    const item = findItem(event, req.params.itemId, isCustom);
    if (item && item.claimants) {
        const idx = item.claimants.findIndex(c => c.name === name);
        if (idx !== -1) {
            item.claimants.splice(idx, 1);
            saveEvent(event);
        }
    }

    res.json(stripHostKey(event));
});

// Add custom item (guest)
app.post('/api/events/:id/custom-items', (req, res) => {
    const event = getEvent(req.params.id);
    if (!event) {
        return res.status(404).json({ error: 'Event not found' });
    }

    const { name, claimedBy, notes } = req.body;
    if (!name || !claimedBy) {
        return res.status(400).json({ error: 'Item name and your name are required' });
    }

    event.customItems = event.customItems || [];
    const item = {
        id: generateId(),
        name,
        claimants: [{ name: claimedBy, notes: notes || '' }],
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
