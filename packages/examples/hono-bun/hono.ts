import { Hono } from "hono";
import { Context } from "hono";
import { cors } from "hono/cors";
import { prettyJSON } from "hono/pretty-json";
import { logger } from "hono/logger";
import { jwt } from "hono/jwt";
import { Auth } from "@skoly/openauth";
import { PostgresAdapter } from "@skoly/openauth/adapters/postgres";
import type { User } from "@skoly/openauth/types";

// JWT secret
const JWT_SECRET = process.env.JWT_SECRET || "4f3c2e1d5b6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d";

// Initialize auth
const db = new PostgresAdapter({
  host: "localhost",
  database: "openauth",
  user: "postgres",
  password: "",
});

const auth = new Auth(db, {
  secret: JWT_SECRET,
});

// Initialize database
db.init().catch(console.error);

// Create auth routes
const authRoutes = new Hono();

// Register endpoint
authRoutes.post("/register", async (c: Context) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.json(
      {
        success: false,
        error: {
          code: "INVALID_INPUT",
          message: "Email and password required",
        },
      },
      400
    );
  }

  const result = await auth.register(email, password, {
    userAgent: c.req.header("user-agent"),
    ipAddress: c.req.header("x-forwarded-for") || c.req.header("x-real-ip"),
  });

  if (!result.success) {
    return c.json(
      {
        success: false,
        error: {
          code: "REGISTRATION_FAILED",
          message: result.error,
        },
      },
      400
    );
  }

  return c.json({
    success: true,
    data: {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      session: result.session,
    },
  });
});

// Login endpoint
authRoutes.post("/login", async (c) => {
  const { email, password } = await c.req.json();

  if (!email || !password) {
    return c.json(
      {
        success: false,
        error: {
          code: "INVALID_INPUT",
          message: "Email and password required",
        },
      },
      400
    );
  }

  const result = await auth.login(email, password, {
    userAgent: c.req.header("user-agent"),
    ipAddress: c.req.header("x-forwarded-for") || c.req.header("x-real-ip"),
  });

  if (!result.success) {
    return c.json(
      {
        success: false,
        error: {
          code: "LOGIN_FAILED",
          message: result.error,
        },
      },
      401
    );
  }

  return c.json({
    success: true,
    data: {
      accessToken: result.accessToken,
      refreshToken: result.refreshToken,
      session: result.session,
    },
  });
});

// Token refresh endpoint
authRoutes.post("/refresh", async (c) => {
  const { refreshToken } = await c.req.json();

  if (!refreshToken) {
    return c.json(
      {
        success: false,
        error: {
          code: "INVALID_INPUT",
          message: "Refresh token required",
        },
      },
      400
    );
  }

  const result = await auth.refreshToken(refreshToken);

  if (!result.success || !result.tokens) {
    return c.json(
      {
        success: false,
        error: {
          code: "REFRESH_FAILED",
          message: result.error || "Failed to refresh tokens",
        },
      },
      401
    );
  }

  return c.json({
    success: true,
    data: {
      accessToken: result.tokens.accessToken,
      refreshToken: result.tokens.refreshToken,
    },
  });
});

// Protected endpoint example
authRoutes.get("/me", async (c) => {
  const authHeader = c.req.header("Authorization");
  if (!authHeader?.startsWith("Bearer ")) {
    return c.json(
      {
        success: false,
        error: {
          code: "UNAUTHORIZED",
          message: "Missing or invalid Authorization header",
        },
      },
      401
    );
  }

  const token = authHeader.split(" ")[1];
  const user = await auth.verifyToken(token);

  if (!user) {
    return c.json(
      {
        success: false,
        error: {
          code: "UNAUTHORIZED",
          message: "Invalid or expired token",
        },
      },
      401
    );
  }

  return c.json({
    success: true,
    data: { user },
  });
});

// Email verification endpoints
authRoutes.post("/verify/start", async (c) => {
  const { email } = await c.req.json();

  if (!email) {
    return c.json(
      {
        success: false,
        error: {
          code: "INVALID_INPUT",
          message: "Email required",
        },
      },
      400
    );
  }

  const token = await auth.generateVerificationToken(email);

  // In a real app, you would send this token via email
  // await sendEmail(email, `Your verification code is: ${token}`);

  return c.json({
    success: true,
    data: {
      message: "Verification code sent",
      token, // Only included for demo purposes
    },
  });
});

authRoutes.post("/verify/complete", async (c) => {
  const { email, token } = await c.req.json();

  if (!email || !token) {
    return c.json(
      {
        success: false,
        error: {
          code: "INVALID_INPUT",
          message: "Email and token required",
        },
      },
      400
    );
  }

  const isValid = await auth.verifyVerificationToken(email, token);
  if (!isValid) {
    return c.json(
      {
        success: false,
        error: {
          code: "INVALID_TOKEN",
          message: "Invalid or expired token",
        },
      },
      400
    );
  }

  return c.json({
    success: true,
    data: {
      message: "Email verified successfully",
    },
  });
});

export function createApp() {
  // Create main app
  const app = new Hono();

  // Global middleware
  app.use("*", logger());
  app.use("*", cors());
  app.use("*", prettyJSON());

  // JWT middleware for protected routes
  const requireAuth = jwt({
    secret: JWT_SECRET,
  });

  // Health check endpoint
  app.get("/health", (c) => {
    return c.json({
      status: "ok",
      timestamp: new Date().toISOString(),
    });
  });

  // Mount auth routes
  app.route("/auth", authRoutes);

  // Protected routes
  const protectedRoutes = new Hono();
  protectedRoutes.use("*", requireAuth);
  protectedRoutes.get("/protected", async (c) => {
    const payload = c.get("jwtPayload");
    const user = await auth.verifyToken(c.req.header("Authorization")?.split(" ")[1] || "");
    
    if (!user) {
      return c.json(
        {
          success: false,
          error: {
            code: "UNAUTHORIZED",
            message: "Invalid or expired token",
          },
        },
        401
      );
    }

    return c.json({ 
      success: true,
      data: {
        payload,
        user
      }
    });
  });
  app.route("/api", protectedRoutes);

  // 404 handler
  app.notFound((c) => {
    return c.json(
      {
        success: false,
        error: {
          code: "NOT_FOUND",
          message: "The requested resource was not found",
        },
      },
      404
    );
  });

  // Error boundary
  app.onError((err, c) => {
    console.error("Unhandled error:", err);

    return c.json(
      {
        success: false,
        error: {
          code: "INTERNAL_SERVER_ERROR",
          message: "An unexpected error occurred",
          error: err.message,
        },
      },
      500
    );
  });

  return { app, db, auth };
}

// Create and export the Bun server configuration
const { app } = createApp();
const port = parseInt(process.env.PORT || "3000");

console.log(`Server running at http://localhost:${port}`);

export default {
  port,
  fetch: app.fetch,
};
