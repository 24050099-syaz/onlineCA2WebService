const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();

const port = 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

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

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:3001",
  "https://onlineca2webservice.onrender.com",
  "https://c219-ca2-team1-811ne51tg-syazs-projects.vercel.app"
];

app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) {
        return callback(null, true);
      }
      return callback(new Error("Not allowed by CORS"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false,
  })
);

function requireAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ error: "Missing token" });

  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ error: "Invalid token format" });
  }

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---------- AUTH ----------
app.post("/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: "Username and password are required" });
  }
  try {
    const [rows] = await pool.execute(
      "SELECT id, username, role, password_hash FROM users WHERE username = ? LIMIT 1",
      [username]
    );
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    const user = rows[0];
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid username or password" });
    }
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );
    return res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role },
    });
  } catch (err) {
    console.error("Login failed:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) {
    return res.status(400).json({ error: "Username, email and password are required" });
  }
  if (username.length < 3) return res.status(400).json({ error: "Username too short" });
  if (!email.includes("@")) return res.status(400).json({ error: "Invalid email" });
  if (password.length < 8) return res.status(400).json({ error: "Password too short" });

  try {
    const [dup] = await pool.execute("SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1", [username, email]);
    if (dup.length > 0) return res.status(409).json({ error: "User already exists" });
    
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);
    const [result] = await pool.execute(
      "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
      [username, email, passwordHash]
    );
    const token = jwt.sign({ userId: result.insertId, username, role: "user" }, JWT_SECRET, { expiresIn: "1h" });
    return res.status(201).json({ token, user: { id: result.insertId, username, role: "user" } });
  } catch (err) {
    res.status(500).json({ error: "Signup failed" });
  }
});

// ---------- EVENTS (CRUD) ----------

app.get("/allevents", async (req, res) => {
    try {
        // Alias image_url as imageUrl for frontend consistency
        const [rows] = await pool.execute("SELECT id, eventName, eventDate, eventDescription, image_url AS imageUrl FROM events");
        res.json(rows);
    } catch {
        res.status(500).json({ error: "Failed to fetch events" });
    }
});

app.post("/addevent", requireAuth, async (req, res) => {
    const { eventName, eventDate, eventDescription, imageUrl } = req.body;
    try {
        await pool.execute(
            "INSERT INTO events (eventName, eventDate, eventDescription, image_url) VALUES (?, ?, ?, ?)",
            [eventName, eventDate, eventDescription, imageUrl]
        );
        res.status(201).json({ message: "Event added" });
    } catch {
        res.status(500).json({ error: "Failed to add event" });
    }
});

app.put("/updateevent/:id", requireAuth, async (req, res) => {
    const { eventName, eventDate, eventDescription, imageUrl } = req.body;
    try {
        await pool.execute(
            "UPDATE events SET eventName = ?, eventDate = ?, eventDescription = ?, image_url = ? WHERE id = ?",
            [eventName, eventDate, eventDescription, imageUrl, req.params.id]
        );
        res.json({ message: "Event updated" });
    } catch {
        res.status(500).json({ error: "Failed to update event" });
    }
});

app.delete("/deleteevent/:id", requireAuth, async (req, res) => {
    try {
        await pool.execute("DELETE FROM event_participants WHERE event_id = ?", [req.params.id]);
        await pool.execute("DELETE FROM events WHERE id = ?", [req.params.id]);
        res.json({ message: "Event deleted" });
    } catch {
        res.status(500).json({ error: "Failed to delete event" });
    }
});

// ---------- JOIN LOGIC ----------

app.get("/my-events", requireAuth, async (req, res) => {
  const userId = req.user.userId;
  try {
    const [rows] = await pool.execute(
      `SELECT e.id, e.eventName, e.eventDescription, e.eventDate, e.image_url AS imageUrl 
       FROM event_participants ep JOIN events e ON e.id = ep.event_id WHERE ep.user_id = ?`,
      [userId]
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch my events" });
  }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});