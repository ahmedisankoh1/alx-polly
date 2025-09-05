// CSRF Protection utilities
// This file implements MEDIUM-001: CSRF Protection

import { cookies } from 'next/headers';
import crypto from 'crypto';

const CSRF_SECRET = process.env.CSRF_SECRET || 'default-csrf-secret-change-in-production';

export function generateCSRFToken(): string {
  const token = crypto.randomBytes(32).toString('hex');
  const timestamp = Date.now().toString();
  const signature = crypto
    .createHmac('sha256', CSRF_SECRET)
    .update(token + timestamp)
    .digest('hex');
  
  return `${token}.${timestamp}.${signature}`;
}

export function validateCSRFToken(token: string): boolean {
  try {
    const [tokenPart, timestamp, signature] = token.split('.');
    
    if (!tokenPart || !timestamp || !signature) {
      return false;
    }
    
    // Check if token is not too old (1 hour)
    const tokenAge = Date.now() - parseInt(timestamp);
    if (tokenAge > 60 * 60 * 1000) {
      return false;
    }
    
    // Verify signature
    const expectedSignature = crypto
      .createHmac('sha256', CSRF_SECRET)
      .update(tokenPart + timestamp)
      .digest('hex');
    
    return crypto.timingSafeEqual(
      Buffer.from(signature, 'hex'),
      Buffer.from(expectedSignature, 'hex')
    );
  } catch {
    return false;
  }
}

export async function getCSRFTokenFromCookie(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get('csrf_token')?.value || null;
}
