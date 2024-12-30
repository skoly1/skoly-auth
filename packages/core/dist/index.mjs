import { jwtVerify, SignJWT, base64url, generateSecret, calculateJwkThumbprint } from 'jose';

var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined") return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});

// src/adapters/postgres.ts
var PostgresAdapter = class {
  constructor(config) {
    this.pool = new (__require("pg")).Pool(config);
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
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

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
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        refresh_token TEXT,
        last_active TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        user_agent TEXT,
        ip_address TEXT
      );

      CREATE TABLE IF NOT EXISTS auth_refresh_tokens (
        token TEXT PRIMARY KEY,
        user_id UUID REFERENCES users(id) ON DELETE CASCADE,
        session_id UUID REFERENCES auth_sessions(id) ON DELETE CASCADE,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        revoked_at TIMESTAMP WITH TIME ZONE
      );

      CREATE TABLE IF NOT EXISTS auth_verification_tokens (
        identifier TEXT NOT NULL,
        token TEXT NOT NULL,
        type TEXT NOT NULL,
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        metadata JSONB,
        PRIMARY KEY (identifier, token)
      );
    `);
  }
  async createUser(email, metadata) {
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
    const values = emails.map(
      (email, i) => `($${i + 1}, CURRENT_TIMESTAMP)`
    ).join(",");
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
    const result = await this.pool.query(
      "SELECT * FROM users WHERE id = $1",
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
    const result = await this.pool.query(
      "SELECT * FROM users WHERE email = $1",
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
    await this.pool.query(
      "UPDATE users SET metadata = $1 WHERE id = $2",
      [JSON.stringify(metadata), id]
    );
  }
  async deleteCredentials(userId) {
    await this.pool.query(
      "DELETE FROM auth_credentials WHERE user_id = $1",
      [userId]
    );
  }
  async deleteSessions(userId) {
    await this.pool.query(
      "DELETE FROM auth_sessions WHERE user_id = $1",
      [userId]
    );
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
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");
      await client.query(
        "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1",
        [id]
      );
      await client.query(
        "DELETE FROM auth_sessions WHERE user_id = $1",
        [id]
      );
      await client.query(
        "DELETE FROM users WHERE id = $1",
        [id]
      );
      await client.query("COMMIT");
    } catch (error) {
      await client.query("ROLLBACK");
      throw error;
    } finally {
      client.release();
    }
  }
  async createCredential(userId, type, identifier, credential) {
    await this.pool.query(
      `INSERT INTO auth_credentials (user_id, type, identifier, credential)
       VALUES ($1, $2, $3, $4)`,
      [userId, type, identifier, credential]
    );
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
    await this.pool.query(
      `UPDATE auth_credentials 
       SET credential = $1, updated_at = CURRENT_TIMESTAMP
       WHERE user_id = $2 AND type = $3`,
      [credential, userId, type]
    );
  }
  async createSession(userId, refreshToken, metadata) {
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
    await this.pool.query(
      "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token = $1",
      [token]
    );
  }
  async revokeUserRefreshTokens(userId) {
    await this.pool.query(
      "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1",
      [userId]
    );
  }
  async deleteSession(id) {
    await this.pool.query(
      "DELETE FROM auth_sessions WHERE id = $1",
      [id]
    );
  }
  async createVerificationToken(identifier, token, type, expiresAt, metadata) {
    await this.pool.query(
      `INSERT INTO auth_verification_tokens (identifier, token, type, expires_at, metadata)
       VALUES ($1, $2, $3, $4, $5)`,
      [identifier, token, type, expiresAt, metadata ? JSON.stringify(metadata) : null]
    );
  }
  async useVerificationToken(identifier, token) {
    const result = await this.pool.query(
      `DELETE FROM auth_verification_tokens
       WHERE identifier = $1 
       AND token = $2
       AND expires_at > CURRENT_TIMESTAMP
       RETURNING *`,
      [identifier, token]
    );
    return result.rows.length > 0;
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
    const timestamp = Date.now().toString();
    const encoded = base64url.encode(new TextEncoder().encode(timestamp));
    for (let i = 0; i < size; i++) {
      bytes[i] = encoded.charCodeAt(i % encoded.length);
    }
    return bytes;
  }
  async hash(data, salt) {
    const secret = await generateSecret("HS256");
    const token = await new SignJWT({ data: salt + data }).setProtectedHeader({ alg: "HS256" }).sign(secret);
    return token;
  }
  async generatePKCEChallenge() {
    const verifierBytes = this.randomBytes(32);
    const verifier = base64url.encode(verifierBytes);
    const jwk = { kty: "oct", k: verifier, alg: "HS256" };
    const challenge = await calculateJwkThumbprint(jwk);
    return {
      codeVerifier: verifier,
      codeChallenge: challenge,
      codeChallengeMethod: "S256"
    };
  }
  async verifyPKCEChallenge(verifier, challenge) {
    const jwk = { kty: "oct", k: verifier, alg: "HS256" };
    const computedChallenge = await calculateJwkThumbprint(jwk);
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
      const salt = Array.from(this.crypto.randomBytes(16)).map((b) => b.toString(16).padStart(2, "0")).join("");
      const hashedPassword = await this.crypto.hash(password, salt);
      await this.db.createCredential(
        user.id,
        "password",
        email,
        `${salt}:${hashedPassword}`
      );
      const tokens = await this.generateTokenPair(user);
      const session = await this.createSession(user.id, tokens.refreshToken, metadata);
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
        return { success: false, error: "Invalid credentials" };
      }
      const credential = await this.db.getCredential(user.id, "password");
      if (!credential) {
        return { success: false, error: "Invalid credentials" };
      }
      const [salt, hash] = credential.credential.split(":");
      const testHash = await this.crypto.hash(password, salt);
      if (hash !== testHash) {
        return { success: false, error: "Invalid credentials" };
      }
      const tokens = await this.generateTokenPair(user);
      const session = await this.createSession(user.id, tokens.refreshToken, metadata);
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
      const { payload } = await jwtVerify(token, this.secret);
      if (!payload.sub || payload.type !== "access") return null;
      const user = await this.db.getUserById(payload.sub);
      return user;
    } catch {
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
    const token = Array.from(this.crypto.randomBytes(3)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 6);
    const expiresAt = new Date(Date.now() + 15 * 60 * 1e3);
    await this.db.createVerificationToken(identifier, token, type, expiresAt, metadata);
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
    const accessToken = await new SignJWT({ email: user.email, type: "access" }).setProtectedHeader({ alg: "HS256" }).setSubject(user.id).setIssuedAt().setExpirationTime(`${this.accessTokenExpiry}s`).sign(this.secret);
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

export { Auth, PostgresAdapter };
//# sourceMappingURL=index.mjs.map
//# sourceMappingURL=index.mjs.map