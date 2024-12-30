interface User {
    id: string;
    email: string;
    createdAt: Date;
}
interface Session {
    id: string;
    userId: string;
    expiresAt: Date;
}
interface VerificationToken {
    identifier: string;
    token: string;
    expiresAt: Date;
}

interface AuthConfig {
    secret: string;
    tokenExpiry?: number;
    secureCookies?: boolean;
}
interface AuthResult {
    success: boolean;
    token?: string;
    error?: string;
}
declare class Auth {
    private config;
    constructor(config: AuthConfig);
    init(): Promise<{
        success: boolean;
    }>;
    createUser(email: string, password: string): Promise<AuthResult>;
    verifyUser(email: string, password: string): Promise<AuthResult>;
}

export { Auth, type AuthConfig, type AuthResult, type Session, type User, type VerificationToken };
