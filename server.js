
const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
require("dotenv").config();

const app = express();

const port = 3000
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

  // Passwords are stored in hash
  try {
    const [rows] = await pool.execute(
      "SELECT id, username, role, password_hash FROM users WHERE username = ? LIMIT 1",
      [username]
    );

    // Generic error msg returns
    if (rows.length === 0) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    const user = rows[0];

    // Check Password
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid username or password" });
    }

    // JWT
    const token = jwt.sign(
      { userId: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    // Debug
    return res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Login failed:", err);
    return res.status(500).json({ error: "Login failed" });
  }
});

// ---------- SIGNUP ----------
app.post("/signup", async (req, res) => {
  const { username, email, password } = req.body || {};

  if (!username || !email || !password) {
    return res
      .status(400)
      .json({ error: "Username, email and password are required" });
  }

  // Input validation
  if (username.length < 3) {
    return res.status(400).json({ error: "Username must be at least 3 characters" });
  }
  if (!email.includes("@")) {
    return res.status(400).json({ error: "Invalid email format" });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: "Password must be at least 8 characters" });
  }

  try {
    // Check if username, email exists
    const [dup] = await pool.execute(
      "SELECT id FROM users WHERE username = ? OR email = ? LIMIT 1",
      [username, email]
    );

    if (dup.length > 0) {
      return res.status(409).json({ error: "Username or email already exists" });
    }
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Add new user
    const [result] = await pool.execute(
      "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
      [username, email, passwordHash]
    );

    // Issue JWT and sign-in
    const token = jwt.sign(
      { userId: result.insertId, username, role: "user" },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    return res.status(201).json({
      token,
      user: {
        id: result.insertId,
        username,
        role: "user",
      },
    });
  } catch (err) {
    console.error("Signup failed:", err);
    return res.status(500).json({ error: "Signup failed" });
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

// ---------- UPDATE EVENT (WEB & MOBILE) ----------
app.put("/updateevent/:id", requireAuth, async (req, res) => {
  const { name, description, event_date, max_participants, image_url, image_url_mobile } = req.body;

  if (!name || !description || !event_date) {
    return res.status(400).json({ error: "Name, description, and event_date are required" });
  }

  // Build the fields dynamically
  const fields = [];
  const values = [];

  fields.push("name = ?");
  values.push(name);

  fields.push("description = ?");
  values.push(description);

  fields.push("event_date = ?");
  values.push(event_date);

  if (typeof max_participants !== "undefined") {
    fields.push("max_participants = ?");
    values.push(max_participants);
  }

  if (typeof image_url !== "undefined") {
    fields.push("image_url = ?");
    values.push(image_url);
  }

  if (typeof image_url_mobile !== "undefined") {
    fields.push("image_url_mobile = ?");
    values.push(image_url_mobile);
  }

  values.push(req.params.id); // Add id for WHERE clause

  const sql = `UPDATE events SET ${fields.join(", ")} WHERE id = ?`;

  try {
    const [result] = await pool.execute(sql, values);

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Event not found" });
    }

    res.json({ message: "Event updated successfully" });
  } catch (err) {
    console.error("PUT /updateevent/:id error:", err);
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


// ---------- EVENTS ----------

// Function to get authenicated user, for retrieval of joined events
function getUserFromAuthHeader(req) {
  const header = req.headers.authorization;
  if (!header) return null;
  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) return null;

  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Get event details
app.get("/events", async (req, res) => {
  try {
    const [rows] = await pool.execute(`
      SELECT
        e.id,
        e.name,
        e.description,
        e.event_date,
        e.max_participants,
        e.image_url,
        COUNT(ep.user_id) AS participant_count
      FROM events e
      LEFT JOIN event_participants ep ON ep.event_id = e.id
      GROUP BY e.id
      ORDER BY e.event_date
    `);
    res.json(rows);
  } catch (err) {
    console.error("GET /events error:", err);
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// Get event by id
app.get("/events/:id", async (req, res) => {
  const user = getUserFromAuthHeader(req);
  const userId = user?.userId || null;

  try {
    const [rows] = await pool.execute(
      `
      SELECT
        e.id,
        e.name,
        e.description,
        e.event_date,
        e.max_participants,
        e.image_url,
        COUNT(ep.user_id) AS participant_count,
        ${userId ? "EXISTS(SELECT 1 FROM event_participants epj WHERE epj.event_id = e.id AND epj.user_id = ?) AS is_joined" : "0 AS is_joined"}
      FROM events e
      LEFT JOIN event_participants ep ON ep.event_id = e.id
      WHERE e.id = ?
      GROUP BY e.id
      LIMIT 1
      `,
      userId ? [userId, req.params.id] : [req.params.id]
    );

    if (!rows.length) return res.status(404).json({ error: "Event not found" });

    const event = rows[0];
    const max = Number(event.max_participants || 0);
    const count = Number(event.participant_count || 0);

    // If event count >= participant count
    event.remaining_slots = max > 0 ? Math.max(max - count, 0) : null;
    event.is_full = max > 0 ? count >= max : false;

    res.json(event);
  } catch (err) {
    console.error("GET /events/:id error:", err);
    res.status(500).json({ error: "Failed to fetch event" });
  }
});

// Post - Join event
app.post("/events/:id/join", requireAuth, async (req, res) => {
  const eventId = Number(req.params.id);
  const userId = req.user.userId;

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    // Prevent race condition, get current participation count
    const [eventRows] = await conn.execute(
      "SELECT id, max_participants, participant_count FROM events WHERE id = ? FOR UPDATE",
      [eventId]
    );

    if (!eventRows.length) {
      await conn.rollback();
      return res.status(404).json({ error: "Event not found" });
    }

    const max = Number(eventRows[0].max_participants || 0);
    const storedCount = Number(eventRows[0].participant_count || 0);

    // If event count >= participant count
    if (max > 0 && storedCount >= max) {
      await conn.rollback();
      return res.status(409).json({ error: "Event is full" });
    }

    // Insert to event_participants
    try {
      await conn.execute(
        "INSERT INTO event_participants (user_id, event_id) VALUES (?, ?)",
        [userId, eventId]
      );
    // User already joined
    } catch (err) {
      if (err && err.code === "ER_DUP_ENTRY") {
        await conn.rollback();
        return res.status(409).json({ error: "Already joined" });
      }
      throw err;
    }

    // Update participant count
    await conn.execute(
      "UPDATE events SET participant_count = participant_count + 1 WHERE id = ?",
      [eventId]
    );

    await conn.commit();
    res.status(201).json({ message: "Joined event" });
  } catch (err) {
    if (conn) await conn.rollback();
    console.error("POST /events/:id/join error:", err);
    res.status(500).json({ error: "Failed to join event" });
  } finally {
    if (conn) conn.release();
  }
});

// Delete - unjoin event
app.delete("/events/:id/join", requireAuth, async (req, res) => {
  const eventId = Number(req.params.id);
  const userId = req.user.userId;

  let conn;
  try {
    conn = await pool.getConnection();
    await conn.beginTransaction();

    const [result] = await conn.execute(
      "DELETE FROM event_participants WHERE user_id = ? AND event_id = ?",
      [userId, eventId]
    );

    // Set participant count to the max - edge cases catch
    if (result.affectedRows > 0) {
      await conn.execute(
        "UPDATE events SET participant_count = GREATEST(participant_count - 1, 0) WHERE id = ?",
        [eventId]
      );
    }

    await conn.commit();
    res.json({ message: "Left event" });
  } catch (err) {
    if (conn) await conn.rollback();
    console.error("DELETE /events/:id/join error:", err);
    res.status(500).json({ error: "Failed to leave event" });
  } finally {
    if (conn) conn.release();
  }
});

// Get list of joined events
app.get("/my-events", requireAuth, async (req, res) => {
  const userId = req.user.userId;

  try {
    const [rows] = await pool.execute(
      `
      SELECT
        e.id,
        e.name,
        e.description,
        e.event_date,
        e.max_participants,
        e.image_url,
        COUNT(ep2.user_id) AS participant_count
      FROM event_participants ep
      JOIN events e ON e.id = ep.event_id
      LEFT JOIN event_participants ep2 ON ep2.event_id = e.id
      WHERE ep.user_id = ?
      GROUP BY e.id
      ORDER BY e.event_date
      `,
      [userId]
    );

    res.json(rows);
  } catch (err) {
    console.error("GET /my-events error:", err);
    res.status(500).json({ error: "Failed to fetch my events" });
  }
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});