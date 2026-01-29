const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 100,
    queueLimit: 0,
};

const pool = mysql.createPool(dbConfig);

app.use(express.json());

app.use(
    cors({
        origin: (origin, callback) => {
            if (!origin) return callback(null, true);
            return callback(null, true);
        },
        methods: ["GET", "POST", "PUT", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization"],
    })
);  

function requireAuth(req, res, next) {
    const header = req.headers.authorization;
    if (!header) return res.status(401).json({ error: "Missing token" });

    const [type, token] = header.split(" ");
    if (type !== "Bearer") return res.status(401).json({ error: "Invalid token" });

    try {
        req.user = jwt.verify(token, JWT_SECRET);
        next();
    } catch {
        res.status(401).json({ error: "Invalid or expired token" });
    }
}

// ---------- AUTH ----------

app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await pool.execute(
            "SELECT id, username FROM users WHERE username = ? AND password = ?",
            [username, password]
        );

        if (rows.length === 0) {
            return res.status(401).json({ error: "Invalid credentials" });
        }

        const token = jwt.sign(
            { userId: rows[0].id, username: rows[0].username },
            JWT_SECRET,
            { expiresIn: "1h" }
        );

        res.json({ token });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Login failed" });
    }
});

// ---------- EVENTS ----------

app.get("/allevents", async (req, res) => {
    try {
        const [rows] = await pool.execute("SELECT * FROM events");
        res.json(rows);
    } catch {
        res.status(500).json({ error: "Failed to fetch events" });
    }
});

app.post("/addevent", requireAuth, async (req, res) => {
    const { eventName, eventDate, eventDescription } = req.body;

    try {
        await pool.execute(
            "INSERT INTO events (eventName, eventDate,eventDescription) VALUES (?, ?,?)",
            [eventName, eventDate,eventDescription]
        );
        res.status(201).json({ message: "Event added" });
    } catch {
        res.status(500).json({ error: "Failed to add event" });
    }
});

app.put("/updateevent/:id", requireAuth, async (req, res) => {
    const { eventName, eventDate,eventDescription } = req.body;

    try {
        await pool.execute(
            "UPDATE events SET eventName = ?, eventDate = ?, eventDescription = ? WHERE id = ?",
            [eventName, eventDate,eventDescription, req.params.id]
        );
        res.json({ message: "Event updated" });
    } catch {
        res.status(500).json({ error: "Failed to update event" });
    }
});

app.delete("/deleteevent/:id", requireAuth, async (req, res) => {
    try {
        await pool.execute(
            "DELETE FROM event_participants WHERE event_id = ?",
            [req.params.id]
        );
        await pool.execute(
            "DELETE FROM events WHERE id = ?",
            [req.params.id]
        );
        res.json({ message: "Event deleted" });
    } catch {
        res.status(500).json({ error: "Failed to delete event" });
    }
});

// ---------- PARTICIPANTS ----------

app.post("/addparticipant", requireAuth, async (req, res) => {
    try {
        await pool.execute(
            "INSERT INTO participants (name) VALUES (?)",
            [req.body.name]
        );
        res.status(201).json({ message: "Participant added" });
    } catch {
        res.status(500).json({ error: "Failed to add participant" });
    }
});

app.post("/events/:eventId/participants", requireAuth, async (req, res) => {
    try {
        await pool.execute(
            "INSERT INTO event_participants (event_id, participant_id) VALUES (?, ?)",
            [req.params.eventId, req.body.participantId]
        );
        res.status(201).json({ message: "Participant linked to event" });
    } catch {
        res.status(500).json({ error: "Failed to link participant" });
    }
});

// ---------- STEP 7: GROUPED JOIN ----------

app.get("/events-with-participants", async (req, res) => {
    try {
        const [rows] = await pool.execute(`
            SELECT 
                e.id AS event_id,
                e.eventName,
                e.eventDate,
                p.id AS participant_id,
                p.name AS participant_name
            FROM events e
            LEFT JOIN event_participants ep ON e.id = ep.event_id
            LEFT JOIN participants p ON ep.participant_id = p.id
            ORDER BY e.eventDate
        `);

        const map = {};

        rows.forEach(r => {
            if (!map[r.event_id]) {
                map[r.event_id] = {
                    id: r.event_id,
                    eventName: r.eventName,
                    eventDate: r.eventDate,
                    participants: []
                };
            }
            if (r.participant_id) {
                map[r.event_id].participants.push({
                    id: r.participant_id,
                    name: r.participant_name
                });
            }
        });

        res.json(Object.values(map));
    } catch {
        res.status(500).json({ error: "Failed to fetch grouped events" });
    }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
