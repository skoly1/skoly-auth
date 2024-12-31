'use strict';

var jose = require('jose');
var bcrypt = require('bcrypt');

function _interopNamespace(e) {
  if (e && e.__esModule) return e;
  var n = Object.create(null);
  if (e) {
    Object.keys(e).forEach(function (k) {
      if (k !== 'default') {
        var d = Object.getOwnPropertyDescriptor(e, k);
        Object.defineProperty(n, k, d.get ? d : {
          enumerable: true,
          get: function () { return e[k]; }
        });
      }
    });
  }
  n.default = e;
  return Object.freeze(n);
}

var bcrypt__namespace = /*#__PURE__*/_interopNamespace(bcrypt);

var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// src/adapters/postgres.ts
var PostgresAdapter = class {
  constructor(config) {
    if (!config) {
      throw new Error("Database configuration is required");
    }
    if (!config.database) {
      throw new Error("Database name is required in configuration");
    }
    const poolConfig = {
      ...config,
      max: config.max || 20,
      // Maximum pool size
      idleTimeoutMillis: config.idleTimeoutMillis || 3e4,
      // Close idle connections after 30s
      connectionTimeoutMillis: config.connectionTimeoutMillis || 2e3
      // Connection timeout
    };
    this.pool = new (__require("pg")).Pool(poolConfig);
    this.pool.on("error", (err) => {
      console.error("Unexpected error on idle client", err);
    });
  }
  /**
   * Initialize database with required tables
   */
  async init() {
    await this.pool.query(`CREATE EXTENSION IF NOT EXISTS "uuid-ossp";`);
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        email TEXT UNIQUE NOT NULL,
        email_verified_at TIMESTAMP WITH TIME ZONE,
        active BOOLEAN DEFAULT true,
        metadata JSONB,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      -- Index for soft deletes
      CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at) WHERE deleted_at IS NULL;

      CREATE TABLE IF NOT EXISTS auth_credentials (
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        type TEXT NOT NULL,
        identifier TEXT NOT NULL,
        credential TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, type)
      );

      CREATE TABLE IF NOT EXISTS auth_sessions (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        user_id UUID REFERENCES users(id) ON DELETE CASCADE NOT NULL,
        refresh_token TEXT NOT NULL,
        last_active TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP NOT NULL,
        user_agent TEXT,
        ip_address TEXT,
        deleted_at TIMESTAMP WITH TIME ZONE
      );

      -- Index for faster session lookups by user
      CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id 
      ON auth_sessions(user_id);

      CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
        token TEXT PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        session_id UUID REFERENCES auth_sessions(id) ON DELETE CASCADE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        revoked_at TIMESTAMP WITH TIME ZONE
      );

      -- Index for faster token lookups by user
      CREATE INDEX IF NOT EXISTS idx_auth_refresh_tokens_user_id 
      ON auth_refresh_tokens(user_id);

      CREATE TABLE IF NOT EXISTS auth_verification_tokens (
        id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
        identifier TEXT NOT NULL,
        token TEXT NOT NULL,
        type TEXT NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        metadata JSONB
      );
      
      -- Index for faster lookups and soft uniqueness
      CREATE INDEX IF NOT EXISTS idx_auth_verification_tokens_identifier 
      ON auth_verification_tokens(identifier);
    `);
  }
  async createUser(email, metadata) {
    if (!email) {
      throw new Error("Email is required");
    }
    const result = await this.pool.query(
      "INSERT INTO users (email, metadata) VALUES ($1, $2) RETURNING *",
      [email.toLowerCase(), metadata ? JSON.stringify(metadata) : null]
    );
    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      active: result.rows[0].active,
      emailVerifiedAt: result.rows[0].email_verified_at,
      metadata: result.rows[0].metadata,
      createdAt: result.rows[0].created_at
    };
  }
  async createUsers(emails) {
    const values = emails.map((email, i) => `($${i + 1}, CURRENT_TIMESTAMP)`).join(",");
    const result = await this.pool.query(
      `INSERT INTO users (email, created_at)
       VALUES ${values}
       RETURNING *`,
      emails.map((email) => email.toLowerCase())
    );
    return result.rows.map((row) => ({
      id: row.id,
      email: row.email,
      active: row.active,
      emailVerifiedAt: row.email_verified_at,
      metadata: row.metadata,
      createdAt: row.created_at
    }));
  }
  async getUserById(id) {
    if (!id) {
      throw new Error("User ID is required");
    }
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      id
    )) {
      throw new Error("Invalid UUID format for user ID");
    }
    console.log(`Getting user by ID: ${id}`);
    const result = await this.pool.query(
      "SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL",
      [id]
    );
    if (result.rows.length === 0) return null;
    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      active: result.rows[0].active,
      emailVerifiedAt: result.rows[0].email_verified_at,
      metadata: result.rows[0].metadata,
      createdAt: result.rows[0].created_at
    };
  }
  async getUserByEmail(email) {
    console.log(`Getting user by email: ${email}`);
    const result = await this.pool.query(
      "SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL",
      [email.toLowerCase()]
    );
    if (result.rows.length === 0) return null;
    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      active: result.rows[0].active,
      emailVerifiedAt: result.rows[0].email_verified_at,
      metadata: result.rows[0].metadata,
      createdAt: result.rows[0].created_at
    };
  }
  async updateUser(id, data) {
    const setFields = [];
    const values = [];
    let paramCount = 1;
    if (data.email !== void 0) {
      setFields.push(`email = $${paramCount}`);
      values.push(data.email.toLowerCase());
      paramCount++;
    }
    if (data.active !== void 0) {
      setFields.push(`active = $${paramCount}`);
      values.push(data.active);
      paramCount++;
    }
    if (data.emailVerifiedAt !== void 0) {
      setFields.push(`email_verified_at = $${paramCount}`);
      values.push(data.emailVerifiedAt);
      paramCount++;
    }
    if (data.metadata !== void 0) {
      setFields.push(`metadata = $${paramCount}`);
      values.push(JSON.stringify(data.metadata));
      paramCount++;
    }
    values.push(id);
    const result = await this.pool.query(
      `UPDATE users 
       SET ${setFields.join(", ")}
       WHERE id = $${paramCount}
       RETURNING *`,
      values
    );
    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      active: result.rows[0].active,
      emailVerifiedAt: result.rows[0].email_verified_at,
      metadata: result.rows[0].metadata,
      createdAt: result.rows[0].created_at
    };
  }
  async setUserMetadata(id, metadata) {
    await this.pool.query("UPDATE users SET metadata = $1 WHERE id = $2", [
      JSON.stringify(metadata),
      id
    ]);
  }
  async deleteCredentials(userId) {
    await this.pool.query("DELETE FROM auth_credentials WHERE user_id = $1", [
      userId
    ]);
  }
  async deleteSessions(userId) {
    await this.pool.query("DELETE FROM auth_sessions WHERE user_id = $1", [
      userId
    ]);
  }
  async transaction(callback) {
    const client = await this.pool.connect();
    const trxAdapter = {
      ...this,
      // Override methods to use transaction client instead of pool
      createUser: async (...args) => {
        const result = await client.query(
          "INSERT INTO users (email, metadata) VALUES ($1, $2) RETURNING *",
          [args[0].toLowerCase(), args[1] ? JSON.stringify(args[1]) : null]
        );
        return {
          id: result.rows[0].id,
          email: result.rows[0].email,
          active: result.rows[0].active,
          emailVerifiedAt: result.rows[0].email_verified_at,
          metadata: result.rows[0].metadata,
          createdAt: result.rows[0].created_at
        };
      },
      // Add other method overrides as needed
      transaction: async (cb) => cb(trxAdapter)
      // Support nested transactions
    };
    try {
      await client.query("BEGIN");
      const result = await callback(trxAdapter);
      await client.query("COMMIT");
      return result;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async deleteUser(id) {
    console.log(`Soft deleting user with ID: ${id}`);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1",
        [id]
      );
      await client.query(
        "UPDATE auth_sessions SET deleted_at = CURRENT_TIMESTAMP WHERE user_id = $1",
        [id]
      );
      await client.query(
        "UPDATE users SET deleted_at = CURRENT_TIMESTAMP, active = false WHERE id = $1",
        [id]
      );
      await client.query("COMMIT");
      console.log(`User ${id} soft deleted successfully`);
    } catch (error) {
      console.error(`Error soft deleting user ${id}:`, error);
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async createCredential(userId, type, identifier, credential) {
    if (!userId) {
      throw new Error("User ID is required");
    }
    if (!type) {
      throw new Error("Credential type is required");
    }
    if (!identifier) {
      throw new Error("Credential identifier is required");
    }
    if (!credential) {
      throw new Error("Credential value is required");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const userResult = await client.query(
        "SELECT id FROM users WHERE id = $1",
        [userId]
      );
      if (userResult.rows.length === 0) {
        throw new Error("User not found");
      }
      await client.query(
        `INSERT INTO auth_credentials (user_id, type, identifier, credential)
         VALUES ($1, $2, $3, $4)`,
        [userId, type, identifier, credential]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async getCredential(userId, type) {
    const result = await this.pool.query(
      "SELECT * FROM auth_credentials WHERE user_id = $1 AND type = $2",
      [userId, type]
    );
    if (result.rows.length === 0) return null;
    return {
      userId: result.rows[0].user_id,
      type: result.rows[0].type,
      identifier: result.rows[0].identifier,
      credential: result.rows[0].credential,
      createdAt: result.rows[0].created_at,
      updatedAt: result.rows[0].updated_at
    };
  }
  async updateCredential(userId, type, credential) {
    if (!userId) {
      throw new Error("User ID is required");
    }
    if (!type) {
      throw new Error("Credential type is required");
    }
    if (!credential) {
      throw new Error("Credential value is required");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `UPDATE auth_credentials 
         SET credential = $1, updated_at = CURRENT_TIMESTAMP
         WHERE user_id = $2 AND type = $3
         RETURNING id`,
        [credential, userId, type]
      );
      if (result.rows.length === 0) {
        throw new Error("Credential not found");
      }
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async createSession(userId, refreshToken, metadata) {
    if (!userId) {
      throw new Error("User ID is required");
    }
    if (!refreshToken) {
      throw new Error("Refresh token is required");
    }
    const result = await this.pool.query(
      `INSERT INTO auth_sessions 
       (id, user_id, refresh_token, expires_at, user_agent, ip_address)
       VALUES (uuid_generate_v4(), $1, $2, $3, $4, $5)
       RETURNING *`,
      [
        userId,
        refreshToken,
        new Date(Date.now() + 30 * 24 * 60 * 60 * 1e3),
        // 30 days
        metadata?.userAgent,
        metadata?.ipAddress
      ]
    );
    return {
      id: result.rows[0].id,
      userId: result.rows[0].user_id,
      refreshToken: result.rows[0].refresh_token,
      lastActive: result.rows[0].last_active,
      expiresAt: result.rows[0].expires_at,
      createdAt: result.rows[0].created_at,
      userAgent: result.rows[0].user_agent,
      ipAddress: result.rows[0].ip_address
    };
  }
  async getSession(id) {
    const result = await this.pool.query(
      "SELECT * FROM auth_sessions WHERE id = $1",
      [id]
    );
    if (result.rows.length === 0) return null;
    return {
      id: result.rows[0].id,
      userId: result.rows[0].user_id,
      refreshToken: result.rows[0].refresh_token,
      lastActive: result.rows[0].last_active,
      expiresAt: result.rows[0].expires_at,
      createdAt: result.rows[0].created_at,
      userAgent: result.rows[0].user_agent,
      ipAddress: result.rows[0].ip_address
    };
  }
  async updateSessionActivity(id) {
    await this.pool.query(
      "UPDATE auth_sessions SET last_active = CURRENT_TIMESTAMP WHERE id = $1",
      [id]
    );
  }
  async getUserSessions(userId) {
    const result = await this.pool.query(
      "SELECT * FROM auth_sessions WHERE user_id = $1 ORDER BY last_active DESC",
      [userId]
    );
    return result.rows.map((row) => ({
      id: row.id,
      userId: row.user_id,
      refreshToken: row.refresh_token,
      lastActive: row.last_active,
      expiresAt: row.expires_at,
      createdAt: row.created_at,
      userAgent: row.user_agent,
      ipAddress: row.ip_address
    }));
  }
  async createRefreshToken(sessionId, userId, token, expiresAt) {
    if (!sessionId) {
      throw new Error("Session ID is required");
    }
    if (!userId) {
      throw new Error("User ID is required");
    }
    if (!token) {
      throw new Error("Token value is required");
    }
    if (!expiresAt) {
      throw new Error("Expiration date is required");
    }
    if (expiresAt.getTime() <= Date.now()) {
      throw new Error("Expiration date must be in the future");
    }
    const result = await this.pool.query(
      `INSERT INTO auth_refresh_tokens (token, user_id, session_id, expires_at)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [token, userId, sessionId, expiresAt]
    );
    return {
      token: result.rows[0].token,
      userId: result.rows[0].user_id,
      sessionId: result.rows[0].session_id,
      expiresAt: result.rows[0].expires_at,
      createdAt: result.rows[0].created_at,
      revokedAt: result.rows[0].revoked_at
    };
  }
  async getRefreshToken(token) {
    const result = await this.pool.query(
      "SELECT * FROM auth_refresh_tokens WHERE token = $1",
      [token]
    );
    if (result.rows.length === 0) return null;
    return {
      token: result.rows[0].token,
      userId: result.rows[0].user_id,
      sessionId: result.rows[0].session_id,
      expiresAt: result.rows[0].expires_at,
      createdAt: result.rows[0].created_at,
      revokedAt: result.rows[0].revoked_at
    };
  }
  async revokeRefreshToken(token) {
    if (!token) {
      throw new Error("Token is required");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const tokenResult = await client.query(
        "SELECT session_id FROM auth_refresh_tokens WHERE token = $1",
        [token]
      );
      if (tokenResult.rows.length === 0) {
        throw new Error("Token not found");
      }
      await client.query(
        "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token = $1",
        [token]
      );
      await client.query(
        "UPDATE auth_sessions SET last_active = CURRENT_TIMESTAMP WHERE id = $1",
        [tokenResult.rows[0].session_id]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async revokeUserRefreshTokens(userId) {
    await this.pool.query(
      "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1",
      [userId]
    );
  }
  async deleteSession(id) {
    await this.pool.query("DELETE FROM auth_sessions WHERE id = $1", [id]);
  }
  async createVerificationToken(identifier, token, type, expiresAt, metadata) {
    if (!identifier) {
      throw new Error("Identifier is required");
    }
    if (!token) {
      throw new Error("Token value is required");
    }
    if (!type) {
      throw new Error("Token type is required");
    }
    if (!["email", "password_reset"].includes(type)) {
      throw new Error(
        "Invalid token type. Must be 'email' or 'password_reset'"
      );
    }
    if (!expiresAt) {
      throw new Error("Expiration date is required");
    }
    if (expiresAt.getTime() <= Date.now()) {
      throw new Error("Expiration date must be in the future");
    }
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        `DELETE FROM auth_verification_tokens 
         WHERE identifier = $1`,
        [identifier]
      );
      await client.query(
        `INSERT INTO auth_verification_tokens (identifier, token, type, expires_at, metadata)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          identifier,
          token,
          type,
          expiresAt,
          metadata ? JSON.stringify(metadata) : null
        ]
      );
      await client.query(
        `DELETE FROM auth_verification_tokens 
         WHERE expires_at < CURRENT_TIMESTAMP 
         AND created_at < CURRENT_TIMESTAMP - INTERVAL '24 hours'`
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async useVerificationToken(identifier, token) {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      const result = await client.query(
        `DELETE FROM auth_verification_tokens
         WHERE identifier = $1 
         AND token = $2
         AND expires_at > CURRENT_TIMESTAMP
         RETURNING type, identifier`,
        [identifier, token]
      );
      if (result.rows.length === 0) {
        await client.query("ROLLBACK");
        return false;
      }
      const { type, identifier: email } = result.rows[0];
      if (type === "email") {
        await client.query(
          `UPDATE users 
           SET email_verified_at = CURRENT_TIMESTAMP 
           WHERE email = $1`,
          [email]
        );
      }
      await client.query("COMMIT");
      return true;
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  /**
   * Close database connection
   */
  async close() {
    await this.pool.end();
  }
};

// src/index.ts
var DefaultCryptoAdapter = class {
  randomBytes(size) {
    const bytes = new Uint8Array(size);
    crypto.getRandomValues(bytes);
    return bytes;
  }
  async hash(data, salt) {
    const saltRounds = 10;
    return await bcrypt__namespace.hash(data, saltRounds);
  }
  async verifyHash(data, hash2) {
    return await bcrypt__namespace.compare(data, hash2);
  }
  async generatePKCEChallenge() {
    const verifierBytes = this.randomBytes(32);
    const verifier = jose.base64url.encode(verifierBytes);
    const jwk = { kty: "oct", k: verifier, alg: "HS256" };
    const challenge = await jose.calculateJwkThumbprint(jwk);
    return {
      codeVerifier: verifier,
      codeChallenge: challenge,
      codeChallengeMethod: "S256"
    };
  }
  async verifyPKCEChallenge(verifier, challenge) {
    const jwk = { kty: "oct", k: verifier, alg: "HS256" };
    const computedChallenge = await jose.calculateJwkThumbprint(jwk);
    return challenge === computedChallenge;
  }
};
var Auth = class {
  constructor(db, config) {
    this.db = db;
    this.secret = new TextEncoder().encode(config.secret);
    this.accessTokenExpiry = config.accessTokenExpiry || 15 * 60;
    this.refreshTokenExpiry = config.refreshTokenExpiry || 7 * 24 * 60 * 60;
    this.sessionExpiry = config.sessionExpiry || 30 * 24 * 60 * 60;
    this.secureCookies = config.secureCookies ?? true;
    this.crypto = config.crypto || new DefaultCryptoAdapter();
  }
  /**
   * Register a new user with email/password
   */
  async register(email, password, metadata) {
    try {
      const existing = await this.db.getUserByEmail(email);
      if (existing) {
        return { success: false, error: "User already exists" };
      }
      const user = await this.db.createUser(email, metadata?.userData);
      const hashedPassword = await this.crypto.hash(password, "");
      await this.db.createCredential(
        user.id,
        "password",
        email,
        hashedPassword
      );
      const tokens = await this.generateTokenPair(user);
      const session = await this.createSession(
        user.id,
        tokens.refreshToken,
        metadata
      );
      return {
        success: true,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        session
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Registration failed"
      };
    }
  }
  /**
   * Login with email/password
   */
  async login(email, password, metadata) {
    try {
      const user = await this.db.getUserByEmail(email);
      if (!user) {
        return { success: false, error: "Authentication failed" };
      }
      const credential = await this.db.getCredential(user.id, "password");
      if (!credential) {
        return { success: false, error: "Authentication failed" };
      }
      const isValid = await this.crypto.verifyHash(
        password,
        credential.credential
      );
      if (!isValid) {
        return { success: false, error: "Authentication failed" };
      }
      const tokens = await this.generateTokenPair(user);
      const session = await this.createSession(
        user.id,
        tokens.refreshToken,
        metadata
      );
      return {
        success: true,
        accessToken: tokens.accessToken,
        refreshToken: tokens.refreshToken,
        session
      };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Login failed"
      };
    }
  }
  /**
   * Verify an access token
   */
  async verifyToken(token) {
    try {
      const { payload } = await jose.jwtVerify(token, this.secret);
      if (!payload.sub || payload.type !== "access") return null;
      const user = await this.db.getUserById(payload.sub);
      return user;
    } catch (error) {
      console.error("Token verification failed:", error);
      return null;
    }
  }
  /**
   * Refresh an access token using a refresh token
   */
  async refreshToken(refreshToken) {
    try {
      const storedToken = await this.db.getRefreshToken(refreshToken);
      if (!storedToken || storedToken.revokedAt) {
        return { success: false, error: "Invalid refresh token" };
      }
      if (storedToken.expiresAt < /* @__PURE__ */ new Date()) {
        await this.db.revokeRefreshToken(refreshToken);
        return { success: false, error: "Refresh token expired" };
      }
      const user = await this.db.getUserById(storedToken.userId);
      if (!user) {
        return { success: false, error: "User not found" };
      }
      const tokens = await this.generateTokenPair(user);
      await this.db.revokeRefreshToken(refreshToken);
      await this.createSession(user.id, tokens.refreshToken);
      return { success: true, tokens };
    } catch (error) {
      return {
        success: false,
        error: error instanceof Error ? error.message : "Token refresh failed"
      };
    }
  }
  /**
   * Logout user by revoking their refresh token
   */
  async logout(refreshToken) {
    await this.db.revokeRefreshToken(refreshToken);
  }
  /**
   * Logout user from all devices by revoking all refresh tokens
   */
  async logoutAll(userId) {
    await this.db.revokeUserRefreshTokens(userId);
  }
  /**
   * Generate a verification token for email/phone verification
   */
  async generateVerificationToken(identifier, type = "email", metadata) {
    const randomBytes = this.crypto.randomBytes(4);
    const number = ((randomBytes[0] | randomBytes[1] << 8 | randomBytes[2] << 16 | (randomBytes[3] & 127) << 24) >>> 0) % 9e5 + 1e5;
    const token = number.toString();
    const expiresAt = new Date(Date.now() + 15 * 60 * 1e3);
    await this.db.createVerificationToken(
      identifier,
      token,
      type,
      expiresAt,
      metadata
    );
    return token;
  }
  /**
   * Verify a verification token
   */
  async verifyVerificationToken(identifier, token) {
    return this.db.useVerificationToken(identifier, token);
  }
  /**
   * Helper to generate access and refresh tokens
   */
  async generateTokenPair(user) {
    const accessToken = await new jose.SignJWT({ email: user.email, type: "access" }).setProtectedHeader({ alg: "HS256" }).setSubject(user.id).setIssuedAt().setExpirationTime(`${this.accessTokenExpiry}s`).sign(this.secret);
    const refreshToken = Array.from(this.crypto.randomBytes(32)).map((b) => b.toString(16).padStart(2, "0")).join("");
    return { accessToken, refreshToken };
  }
  /**
   * Helper to create a new session with refresh token
   */
  async createSession(userId, refreshToken, metadata) {
    new Date(Date.now() + this.sessionExpiry * 1e3);
    const session = await this.db.createSession(userId, refreshToken, metadata);
    await this.db.createRefreshToken(
      session.id,
      userId,
      refreshToken,
      new Date(Date.now() + this.refreshTokenExpiry * 1e3)
    );
    return session;
  }
};

exports.Auth = Auth;
exports.PostgresAdapter = PostgresAdapter;
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map