import { Hono } from "hono";
import { cors } from "hono/cors";
import { prettyJSON } from "hono/pretty-json";
import { logger } from "hono/logger";
import { Auth } from "@skoly/openauth";
import { PostgresAdapter } from "@skoly/openauth/adapters/postgres";

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";

// Initialize database adapter
const db = new PostgresAdapter({
  host: "localhost",
  database: "openauth",
  user: "postgres",
  password: "",
});

// Initialize auth
const auth = new Auth(db, {
  secret: JWT_SECRET,
});

// Initialize database
db.init().catch(console.error);

// Create Hono app
const app = new Hono();

// Global middleware
app.use("*", logger());
app.use("*", cors());
app.use("*", prettyJSON());

// Health check endpoint
app.get("/health", (c) => {
  return c.json({ status: "ok", timestamp: new Date().toISOString() });
});

// Register endpoint
app.post("/register", async (c) => {
  const { email, password } = await c.req.json();
  const result = await auth.register(email, password);
  return c.json(result);
});

// Login endpoint
app.post("/login", async (c) => {
  const { email, password } = await c.req.json();
  const result = await auth.login(email, password);
  return c.json(result);
});

// Token refresh endpoint
app.post("/refresh", async (c) => {
  const { refreshToken } = await c.req.json();
  const result = await auth.refreshToken(refreshToken);
  return c.json(result);
});

// Logout endpoint
app.post("/logout", async (c) => {
  const { refreshToken } = await c.req.json();
  await auth.logout(refreshToken);
  return c.json({ success: true, message: "Logged out successfully" });
});

// Logout from all devices endpoint
app.post("/logout-all", async (c) => {
  const { userId } = await c.req.json();
  await auth.logoutAll(userId);
  return c.json({ success: true, message: "Logged out from all devices" });
});

// Verify token endpoint
app.post("/verify-token", async (c) => {
  const { token } = await c.req.json();
  const user = await auth.verifyToken(token);
  return c.json({ success: !!user, user });
});

// Generate verification token endpoint
app.post("/generate-verification-token", async (c) => {
  const { identifier, type } = await c.req.json();
  const token = await auth.generateVerificationToken(identifier, type);
  return c.json({ success: true, token });
});

// Verify verification token endpoint
app.post("/verify-verification-token", async (c) => {
  const { identifier, token } = await c.req.json();
  const isValid = await auth.verifyVerificationToken(identifier, token);
  return c.json({ success: isValid });
});

// Get user by ID endpoint
app.get("/user/:id", async (c) => {
  const { id } = c.req.param();
  const user = await db.getUserById(id);
  return c.json({ success: !!user, user });
});

// Get user by email endpoint
app.get("/user/email/:email", async (c) => {
  const { email } = c.req.param();
  const user = await db.getUserByEmail(email);
  return c.json({ success: !!user, user });
});

// Update user endpoint
app.put("/user/:id", async (c) => {
  const { id } = c.req.param();
  const data = await c.req.json();
  const user = await db.updateUser(id, data);
  return c.json({ success: !!user, user });
});

// Delete user endpoint
app.delete("/user/:id", async (c) => {
  const { id } = c.req.param();
  await db.deleteUser(id);
  return c.json({ success: true, message: "User deleted successfully" });
});

// Get user sessions endpoint
app.get("/user/:id/sessions", async (c) => {
  const { id } = c.req.param();
  const sessions = await db.getUserSessions(id);
  return c.json({ success: true, sessions });
});

// Get refresh token endpoint
app.get("/refresh-token/:token", async (c) => {
  const { token } = c.req.param();
  const refreshToken = await db.getRefreshToken(token);
  return c.json({ success: !!refreshToken, refreshToken });
});

// Revoke refresh token endpoint
app.post("/revoke-refresh-token", async (c) => {
  const { token } = await c.req.json();
  await db.revokeRefreshToken(token);
  return c.json({ success: true, message: "Refresh token revoked" });
});

// Revoke all refresh tokens for a user endpoint
app.post("/revoke-user-refresh-tokens", async (c) => {
  const { userId } = await c.req.json();
  await db.revokeUserRefreshTokens(userId);
  return c.json({ success: true, message: "All refresh tokens revoked" });
});

// 404 handler
app.notFound((c) => {
  return c.json({ success: false, error: "Not Found" }, 404);
});

// Error boundary
app.onError((err, c) => {
  console.error("Unhandled error:", err);
  return c.json({ success: false, error: "Internal Server Error" }, 500);
});

// Start the server
const port = parseInt(process.env.PORT || "3000");
console.log(`Server running at http://localhost:${port}`);

export default {
  port,
  fetch: app.fetch,
};
