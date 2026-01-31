# EventEco Web Service

**EventEco Web Service** is a backend REST API developed to support event management and participation for both **web** and **mobile clients**.  
It handles authentication, event data storage, and event participation using a centralized database.

---

## What is this web service about?

This web service was developed as part of a project to provide a **central backend system** for managing events.  
It exposes **RESTful API endpoints** that allow clients to:

- Authenticate users
- Manage events
- Track event participation

---

## Notable Features of the Web Service

- User authentication (login and signup)  
- JWT-based authorization  
- Event creation, retrieval, updating, and deletion  
- Event participation (join and leave)  
- Participant count tracking  
- MySQL database integration  
- Secure password hashing  

---

## Backend Web Service

The table below documents the **available API routes** provided by the web service.

### API Routes Documentation

| Route | HTTP Method | Description | Request Body / Parameters |
|-------|------------|-------------|---------------------------|
| `/login` | POST | Authenticates a user | JSON: `{ "username", "password" }` |
| `/signup` | POST | Registers a new user | JSON: `{ "username", "email", "password" }` |
| `/events` | GET | Retrieves all events | None |
| `/events/:id` | GET | Retrieves details of a specific event | URL param: `id` |
| `/addevent` | POST | Adds a new event (authenticated users only) | JSON: `{ "name", "description", "event_date", "images" }` |
| `/updateevent/:id` | PUT | Updates an existing event | URL param: `id` + JSON body |
| `/deleteevent/:id` | DELETE | Deletes a specific event | URL param: `id` |
| `/events/:id/join` | POST | Join an event | URL param: `id` |
| `/events/:id/join` | DELETE | Leave an event | URL param: `id` |
| `/my-events` | GET | Retrieves events joined by the user | Auth token |

---

## Team Contributions

This project was completed by a single developer.

| Name | Role | Responsibilities |
|------|------|------------------|
| **Syazwan** | Backend Developer | Backend web service, database integration, authentication, event management features, API routes, and documentation |
| **Brian** | Backend Developer | API Routes|
