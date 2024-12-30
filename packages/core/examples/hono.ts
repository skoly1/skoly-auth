import express from 'express';
import { Auth } from 'src';
import { PostgresAdapter } from 'src/adapters/postgres';
import type { User } from 'src/types';

// Extend Express Request type to include user
declare global {
  namespace Express {
    interface Request {
      user?: User;
    }
  }
}

export function createApp() {
  const app = express();
  app.use(express.json());

  // Initialize auth
  const db = new PostgresAdapter({
    host: 'localhost',
    database: 'myapp',
    user: 'postgres',
    password: 'postgres'
  });

  const auth = new Auth(db, {
    secret: process.env.JWT_SECRET || 'your-secret-key'
  });

  // Initialize database
  db.init().catch(console.error);

  // Middleware to verify JWT token
  const requireAuth = async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
      return res.status(401).json({ error: 'No token provided' });
    }

    const user = await auth.verifyToken(token);
    if (!user) {
      return res.status(401).json({ error: 'Invalid token' });
    }

    req.user = user;
    next();
  };

  // Register endpoint
  app.post('/auth/register', async (req: express.Request, res: express.Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await auth.register(email, password);
    if (!result.success) {
      return res.status(400).json({ error: result.error });
    }

    res.json({ token: result.token });
  });

  // Login endpoint
  app.post('/auth/login', async (req: express.Request, res: express.Response) => {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    const result = await auth.login(email, password);
    if (!result.success) {
      return res.status(401).json({ error: result.error });
    }

    res.json({ token: result.token });
  });

  // Protected endpoint example
  app.get('/protected', requireAuth, (req: express.Request, res: express.Response) => {
    res.json({ user: req.user });
  });

  // Email verification endpoints
  app.post('/auth/verify/start', async (req: express.Request, res: express.Response) => {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ error: 'Email required' });
    }

    const token = await auth.generateVerificationToken(email);
    
    // In a real app, you would send this token via email
    // await sendEmail(email, `Your verification code is: ${token}`);
    
    res.json({ message: 'Verification code sent', token });
  });

  app.post('/auth/verify/complete', async (req: express.Request, res: express.Response) => {
    const { email, token } = req.body;
    if (!email || !token) {
      return res.status(400).json({ error: 'Email and token required' });
    }

    const isValid = await auth.verifyVerificationToken(email, token);
    if (!isValid) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    res.json({ message: 'Email verified successfully' });
  });

  return { app, db, auth };
}

// Only start server if this file is run directly
if (import.meta.url === new URL(process.argv[1], 'file:').href) {
  const { app } = createApp();
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}
