const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();
const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

// Database Configuration based on your schema
const dbConfig = {
  host: process.env.DB_HOST || "",
  user: process.env.DB_USER || "",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "",
  port: process.env.DB_PORT ? Number(process.env.DB_PORT) : 3306,
  waitForConnections: true,
  connectionLimit: 100,
  queueLimit: 0,
};

const pool = mysql.createPool(dbConfig);
app.use(express.json());

// CORS Configuration
const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "https://onlineca2webservice.onrender.com",
  "https://c219-ca2-team1-fmc2b9n1s-syazs-projects.vercel.app"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Authentication Middleware
function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing token" });

  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) return res.status(401).json({ error: "Invalid token format" });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---------- AUTH ROUTES ----------

app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  try {
    const [rows] = await pool.execute(
      "SELECT id, username, role, password_hash FROM users WHERE username = ? LIMIT 1",
      [username]
    );
    if (rows.length === 0) return res.status(401).json({ error: "Invalid username or password" });

    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid username or password" });

    const token = jwt.sign({ userId: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: "1h" });
    res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body || {};
  try {
    const [dup] = await pool.execute("SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1", [username, email]);
    if (dup.length > 0) return res.status(409).json({ error: "Username or email already exists" });

    const passwordHash = await bcrypt.hash(password, 10);
    const [result] = await pool.execute(
      "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
      [username, email, passwordHash]
    );

    const token = jwt.sign({ userId: result.insertId, username, role: "user" }, JWT_SECRET, { expiresIn: "1h" });
    res.status(201).json({ token, user: { id: result.insertId, username, role: "user" } });
  } catch (err) {
    res.status(500).json({ error: "Signup failed" });
  }
});

// ---------- EVENT ROUTES (Standardized for Web & Mobile) ----------

// Get all events with aliases to match frontend camelCase
app.get("/allevents", async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT 
        id, 
        name AS eventName, 
        description AS eventDescription, 
        event_date AS eventDate, 
        image_url AS imageUrl, 
        image_url_mobile AS imageUrlMobile 
      FROM events
    `);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// Add event handling both image URLs
app.post("/addevent", requireAuth, async (req, res) => {
  const { eventName, eventDate, eventDescription, imageUrl, imageUrlMobile } = req.body;
  try {
    await pool.execute(
      "INSERT INTO events (name, event_date, description, image_url, image_url_mobile) VALUES (?, ?, ?, ?, ?)",
      [eventName, eventDate, eventDescription, imageUrl, imageUrlMobile]
    );
    res.status(201).json({ message: "Event added" });
  } catch (err) {
    res.status(500).json({ error: "Failed to add event" });
  }
});

// Update event mapping camelCase back to snake_case
app.put("/updateevent/:id", requireAuth, async (req, res) => {
  const { eventName, eventDate, eventDescription, imageUrl, imageUrlMobile } = req.body;
  try {
    await pool.execute(
      `UPDATE events SET 
        name = ?, 
        event_date = ?, 
        description = ?, 
        image_url = ?, 
        image_url_mobile = ? 
      WHERE id = ?`,
      [eventName, eventDate, eventDescription, imageUrl, imageUrlMobile, req.params.id]
    );
    res.json({ message: "Event updated" });
  } catch (err) {
    res.status(500).json({ error: "Failed to update event" });
  }
});

app.delete("/deleteevent/:id", requireAuth, async (req, res) => {
  try {
    await pool.execute("DELETE FROM event_participants WHERE event_id = ?", [req.params.id]);
    await pool.execute("DELETE FROM events WHERE id = ?", [req.params.id]);
    res.json({ message: "Event deleted" });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete event" });
  }
});

// ---------- PARTICIPATION ROUTES ----------

app.post("/events/:id/join", requireAuth, async (req, res) => {
  const eventId = req.params.id;
  const userId = req.user.userId;
  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();
    await conn.execute("INSERT INTO event_participants (user_id, event_id) VALUES (?, ?)", [userId, eventId]);
    await conn.execute("UPDATE events SET participant_count = participant_count + 1 WHERE id = ?", [eventId]);
    await conn.commit();
    res.status(201).json({ message: "Joined event" });
  } catch (err) {
    if (conn) await conn.rollback();
    res.status(500).json({ error: "Failed to join event" });
  } finally {
    if (conn) conn.release();
  }
});

app.get("/my-events", requireAuth, async (req, res) => {
  try {
    const [rows] = await pool.execute(
      `SELECT e.id, e.name AS eventName, e.description AS eventDescription, e.event_date AS eventDate, 
              e.image_url AS imageUrl, e.image_url_mobile AS imageUrlMobile
       FROM event_participants ep 
       JOIN events e ON e.id = ep.event_id 
       WHERE ep.user_id = ?`,
      [req.user.userId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch joined events" });
  }
});

app.listen(port, () => console.log(`Server running on port ${port}`));