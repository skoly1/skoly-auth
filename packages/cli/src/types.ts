export type DatabaseType = 'postgres' | 'mongodb' | 'mysql' | 'sqlite';

export interface AuthConfig {
  jwtSecret: string;
  sessionDuration: string;
  passwordRequirements: {
    minLength: number;
    requireNumbers: boolean;
    requireSpecialChars: boolean;
  };
}
