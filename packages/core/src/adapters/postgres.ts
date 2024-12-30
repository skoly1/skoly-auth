import type { Pool, PoolConfig } from 'pg';
import type {
  DatabaseAdapter,
  User,
  Credential,
  Session,
  VerificationToken,
  RefreshToken
} from '../types';

/**
 * PostgreSQL implementation of the DatabaseAdapter interface
 */
export class PostgresAdapter implements DatabaseAdapter {
  private pool: Pool;

  constructor(config: PoolConfig) {
    // We use dynamic import to avoid bundling pg when not used
    this.pool = new (require('pg').Pool)(config);
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
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (identifier, token)
      );
    `);
  }

  async createUser(email: string): Promise<User> {
    const result = await this.pool.query(
      'INSERT INTO users (email) VALUES ($1) RETURNING *',
      [email.toLowerCase()]
    );
    
    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      createdAt: result.rows[0].created_at
    };
  }

  async getUserById(id: string): Promise<User | null> {
    const result = await this.pool.query(
      'SELECT * FROM users WHERE id = $1',
      [id]
    );

    if (result.rows.length === 0) return null;

    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      createdAt: result.rows[0].created_at
    };
  }

  async getUserByEmail(email: string): Promise<User | null> {
    const result = await this.pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) return null;

    return {
      id: result.rows[0].id,
      email: result.rows[0].email,
      createdAt: result.rows[0].created_at
    };
  }

  async createCredential(
    userId: string,
    type: string,
    identifier: string,
    credential: string
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO auth_credentials (user_id, type, identifier, credential)
       VALUES ($1, $2, $3, $4)`,
      [userId, type, identifier, credential]
    );
  }

  async getCredential(userId: string, type: string): Promise<Credential | null> {
    const result = await this.pool.query(
      'SELECT * FROM auth_credentials WHERE user_id = $1 AND type = $2',
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

  async updateCredential(
    userId: string,
    type: string,
    credential: string
  ): Promise<void> {
    await this.pool.query(
      `UPDATE auth_credentials 
       SET credential = $1, updated_at = CURRENT_TIMESTAMP
       WHERE user_id = $2 AND type = $3`,
      [credential, userId, type]
    );
  }

  async createSession(
    userId: string, 
    refreshToken: string,
    metadata?: { userAgent?: string; ipAddress?: string }
  ): Promise<Session> {
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

  async getSession(id: string): Promise<Session | null> {
    const result = await this.pool.query(
      'SELECT * FROM auth_sessions WHERE id = $1',
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

  async updateSessionActivity(id: string): Promise<void> {
    await this.pool.query(
      'UPDATE auth_sessions SET last_active = CURRENT_TIMESTAMP WHERE id = $1',
      [id]
    );
  }

  async getUserSessions(userId: string): Promise<Session[]> {
    const result = await this.pool.query(
      'SELECT * FROM auth_sessions WHERE user_id = $1 ORDER BY last_active DESC',
      [userId]
    );

    return result.rows.map(row => ({
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

  async createRefreshToken(
    sessionId: string,
    userId: string,
    token: string,
    expiresAt: Date
  ): Promise<RefreshToken> {
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

  async getRefreshToken(token: string): Promise<RefreshToken | null> {
    const result = await this.pool.query(
      'SELECT * FROM auth_refresh_tokens WHERE token = $1',
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

  async revokeRefreshToken(token: string): Promise<void> {
    await this.pool.query(
      'UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE token = $1',
      [token]
    );
  }

  async revokeUserRefreshTokens(userId: string): Promise<void> {
    await this.pool.query(
      'UPDATE auth_refresh_tokens SET revoked_at = CURRENT_TIMESTAMP WHERE user_id = $1',
      [userId]
    );
  }

  async deleteSession(id: string): Promise<void> {
    await this.pool.query(
      'DELETE FROM auth_sessions WHERE id = $1',
      [id]
    );
  }

  async createVerificationToken(
    identifier: string,
    token: string,
    expiresAt: Date
  ): Promise<void> {
    await this.pool.query(
      `INSERT INTO auth_verification_tokens (identifier, token, expires_at)
       VALUES ($1, $2, $3)`,
      [identifier, token, expiresAt]
    );
  }

  async useVerificationToken(
    identifier: string,
    token: string
  ): Promise<boolean> {
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
  async close(): Promise<void> {
    await this.pool.end();
  }
}
