import { randomUUID } from 'node:crypto';
import type { Pool, PoolConfig } from 'pg';
import type {
  DatabaseAdapter,
  User,
  Credential,
  Session,
  VerificationToken
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
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );

      CREATE TABLE IF NOT EXISTS auth_credentials (
        user_id TEXT REFERENCES users(id),
        type TEXT NOT NULL,
        identifier TEXT NOT NULL,
        credential TEXT NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (user_id, type)
      );

      CREATE TABLE IF NOT EXISTS auth_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT REFERENCES users(id),
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
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
      'INSERT INTO users (id, email) VALUES ($1, $2) RETURNING *',
      [randomUUID(), email.toLowerCase()]
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

  async createSession(userId: string, expiresAt: Date): Promise<Session> {
    const result = await this.pool.query(
      `INSERT INTO auth_sessions (id, user_id, expires_at)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [randomUUID(), userId, expiresAt]
    );

    return {
      id: result.rows[0].id,
      userId: result.rows[0].user_id,
      expiresAt: result.rows[0].expires_at,
      createdAt: result.rows[0].created_at
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
      expiresAt: result.rows[0].expires_at,
      createdAt: result.rows[0].created_at
    };
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
