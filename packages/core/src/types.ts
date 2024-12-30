// packages/core/src/types.ts

export interface User {
    id: string
    email: string
    createdAt: Date
  }
  
  export interface Session {
    id: string
    userId: string
    expiresAt: Date
  }
  
  export interface VerificationToken {
    identifier: string
    token: string
    expiresAt: Date
  }