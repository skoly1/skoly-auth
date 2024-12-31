import type { Pool, PoolConfig } from "pg";
import type {
  DatabaseAdapter,
  User,
  Credential,
  Session,
  VerificationToken,
  RefreshToken,
} from "../types";

/**
 * PostgreSQL implementation of the DatabaseAdapter interface
 */
export class PostgresAdapter implements DatabaseAdapter {
  private pool: Pool;

  constructor(config: PoolConfig) {
    if (!config) {
      throw new Error("Database configuration is required");
    }
    if (!config.database) {
      throw new Error("Database name is required in configuration");
    }

    // Configure connection pool with optimal defaults
    const poolConfig = {
      ...config,
      max: config.max || 20, // Maximum pool size
      idleTimeoutMillis: config.idleTimeoutMillis || 30000, // Close idle connections after 30s
      connectionTimeoutMillis: config.connectionTimeoutMillis || 2000, // Connection timeout
    };

    // We use dynamic import to avoid bundling pg when not used
    this.pool = new (require("pg").Pool)(poolConfig);

    // Setup pool error handler
    this.pool.on("error", (err) => {
      console.error("Unexpected error on idle client", err);
    });
  }

  /**
   * Initialize database with required tables
   */
  async init(): Promise<void> {
    // Enable UUID extension if not enabled
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

  async createUser(
    email: string,
    metadata?: Record<string, any>
  ): Promise<User> {
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
      createdAt: result.rows[0].created_at,
    };
  }

  async createUsers(emails: string[]): Promise<User[]> {
    const values = emails
      .map((email, i) => `($${i + 1}, CURRENT_TIMESTAMP)`)
      .join(",");

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
      createdAt: row.created_at,
    }));
  }

  async getUserById(id: string): Promise<User | null> {
    if (!id) {
      throw new Error("User ID is required");
    }
    if (
      !/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
        id
      )
    ) {
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
      createdAt: result.rows[0].created_at,
    };
  }

  async getUserByEmail(email: string): Promise<User | null> {
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
      createdAt: result.rows[0].created_at,
    };
  }

  async updateUser(id: string, data: Partial<User>): Promise<User> {
    const setFields = [];
    const values = [];
    let paramCount = 1;

    if (data.email !== undefined) {
      setFields.push(`email = $${paramCount}`);
      values.push(data.email.toLowerCase());
      paramCount++;
    }
    if (data.active !== undefined) {
      setFields.push(`active = $${paramCount}`);
      values.push(data.active);
      paramCount++;
    }
    if (data.emailVerifiedAt !== undefined) {
      setFields.push(`email_verified_at = $${paramCount}`);
      values.push(data.emailVerifiedAt);
      paramCount++;
    }
    if (data.metadata !== undefined) {
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
      createdAt: result.rows[0].created_at,
    };
  }

  async setUserMetadata(
    id: string,
    metadata: Record<string, any>
  ): Promise<void> {
    await this.pool.query("UPDATE users SET metadata = $1 WHERE id = $2", [
      JSON.stringify(metadata),
      id,
    ]);
  }

  async deleteCredentials(userId: string): Promise<void> {
    await this.pool.query("DELETE FROM auth_credentials WHERE user_id = $1", [
      userId,
    ]);
  }

  async deleteSessions(userId: string): Promise<void> {
    await this.pool.query("DELETE FROM auth_sessions WHERE user_id = $1", [
      userId,
    ]);
  }

  async transaction<T>(
    callback: (trx: DatabaseAdapter) => Promise<T>
  ): Promise<T> {
    const client = await this.pool.connect();

    // Create a transaction-scoped adapter that uses the client directly
    const trxAdapter: DatabaseAdapter = {
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
          createdAt: result.rows[0].created_at,
        };
      },
      // Add other method overrides as needed
      transaction: async (cb) => cb(trxAdapter), // Support nested transactions
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

  async deleteUser(id: string): Promise<void> {
    console.log(`Soft deleting user with ID: ${id}`);
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      // Revoke all tokens
      await client.query(
        "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1",
        [id]
      );

      // Soft delete sessions
      await client.query(
        "UPDATE auth_sessions SET deleted_at = CURRENT_TIMESTAMP WHERE user_id = $1",
        [id]
      );

      // Soft delete user
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

  async createCredential(
    userId: string,
    type: string,
    identifier: string,
    credential: string
  ): Promise<void> {
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

      // Verify user exists
      const userResult = await client.query(
        "SELECT id FROM users WHERE id = $1",
        [userId]
      );
      if (userResult.rows.length === 0) {
        throw new Error("User not found");
      }

      // Create credential
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

  async getCredential(
    userId: string,
    type: string
  ): Promise<Credential | null> {
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
      updatedAt: result.rows[0].updated_at,
    };
  }

  async updateCredential(
    userId: string,
    type: string,
    credential: string
  ): Promise<void> {
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

      // Update credential and verify it exists
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

  async createSession(
    userId: string,
    refreshToken: string,
    metadata?: { userAgent?: string; ipAddress?: string }
  ): Promise<Session> {
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
        new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
        metadata?.userAgent,
        metadata?.ipAddress,
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
      ipAddress: result.rows[0].ip_address,
    };
  }

  async getSession(id: string): Promise<Session | null> {
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
      ipAddress: result.rows[0].ip_address,
    };
  }

  async updateSessionActivity(id: string): Promise<void> {
    await this.pool.query(
      "UPDATE auth_sessions SET last_active = CURRENT_TIMESTAMP WHERE id = $1",
      [id]
    );
  }

  async getUserSessions(userId: string): Promise<Session[]> {
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
      ipAddress: row.ip_address,
    }));
  }

  async createRefreshToken(
    sessionId: string,
    userId: string,
    token: string,
    expiresAt: Date
  ): Promise<RefreshToken> {
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
      revokedAt: result.rows[0].revoked_at,
    };
  }

  async getRefreshToken(token: string): Promise<RefreshToken | null> {
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
      revokedAt: result.rows[0].revoked_at,
    };
  }

  async revokeRefreshToken(token: string): Promise<void> {
    if (!token) {
      throw new Error("Token is required");
    }

    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      // Get token info
      const tokenResult = await client.query(
        "SELECT session_id FROM auth_refresh_tokens WHERE token = $1",
        [token]
      );

      if (tokenResult.rows.length === 0) {
        throw new Error("Token not found");
      }

      // Revoke token
      await client.query(
        "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token = $1",
        [token]
      );

      // Update session last_active
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

  async revokeUserRefreshTokens(userId: string): Promise<void> {
    await this.pool.query(
      "UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1",
      [userId]
    );
  }

  async deleteSession(id: string): Promise<void> {
    await this.pool.query("DELETE FROM auth_sessions WHERE id = $1", [id]);
  }

  async createVerificationToken(
    identifier: string,
    token: string,
    type: "email" | "password_reset",
    expiresAt: Date,
    metadata?: Record<string, any>
  ): Promise<void> {
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

      // Delete any existing tokens for this identifier
      await client.query(
        `DELETE FROM auth_verification_tokens 
         WHERE identifier = $1`,
        [identifier]
      );

      // Create new token
      await client.query(
        `INSERT INTO auth_verification_tokens (identifier, token, type, expires_at, metadata)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          identifier,
          token,
          type,
          expiresAt,
          metadata ? JSON.stringify(metadata) : null,
        ]
      );

      // Cleanup expired tokens older than 24 hours
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

  async useVerificationToken(
    identifier: string,
    token: string
  ): Promise<boolean> {
    const client = await this.pool.connect();
    try {
      await client.query("BEGIN");

      // Get and delete the verification token
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

      // Handle different token types
      if (type === "email") {
        // Update user's email verification status
        await client.query(
          `UPDATE users 
           SET email_verified_at = CURRENT_TIMESTAMP 
           WHERE email = $1`,
          [email]
        );
      }
      // Note: For password_reset type, the actual password update is handled separately
      // since we don't want to store the new password in the verification token

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
  async close(): Promise<void> {
    await this.pool.end();
  }
}
