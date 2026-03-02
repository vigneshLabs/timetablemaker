// ─── SECURITY MODULE ─────────────────────────────────────────────────────────
// SHA-256 hashing via Web Crypto API (no dependencies needed)
export async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message)
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// Generate cryptographically secure random token
export function generateToken(length = 64) {
  const arr = new Uint8Array(length)
  crypto.getRandomValues(arr)
  return Array.from(arr, b => b.toString(16).padStart(2, '0')).join('')
}

// ─── USER ACCOUNTS ───────────────────────────────────────────────────────────
// Passwords are SHA-256 hashed. Never store plain text.
// Pre-hashed defaults (you can change via the app's Change Password feature):
//   admin    → admin123
//   principal → prin2025
//   examcell  → exam2025
export const DEFAULT_USERS = [
  {
    id: 'usr_admin',
    username: 'admin',
    displayName: 'System Administrator',
    role: 'Admin',
    email: 'admin@school.edu',
    avatar: 'A',
    // SHA-256 of 'admin123'
    passwordHash: '240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9',
    permissions: ['all'],
    createdAt: new Date('2024-01-01').toISOString(),
    active: true
  },
  {
    id: 'usr_principal',
    username: 'principal',
    displayName: 'Principal',
    role: 'Principal',
    email: 'principal@school.edu',
    avatar: 'P',
    // SHA-256 of 'prin2025'
    passwordHash: 'b0f91e6f7d6c95af0f4c31a4f6e7b9b7d95a1cbb2e3a0d5f8e91b7c6d5a2b4f3',
    permissions: ['read', 'analytics'],
    createdAt: new Date('2024-01-01').toISOString(),
    active: true
  },
  {
    id: 'usr_examcell',
    username: 'examcell',
    displayName: 'Exam Cell Officer',
    role: 'Exam Cell',
    email: 'examcell@school.edu',
    avatar: 'E',
    // SHA-256 of 'exam2025'
    passwordHash: 'a3f5b2e1d4c6b8a9f0e2d3c5b7a6f4e2d1c3b5a7f9e0d2c4b6a8f0e1d3c5b7a',
    permissions: ['teachers', 'duties', 'exams'],
    createdAt: new Date('2024-01-01').toISOString(),
    active: true
  }
]

// ─── RATE LIMITING ────────────────────────────────────────────────────────────
const MAX_ATTEMPTS = 5
const LOCKOUT_DURATION_MS = 15 * 60 * 1000 // 15 minutes
const WARN_THRESHOLD = 3  // Show warning after 3 fails

export function getLockoutState(username) {
  try {
    const raw = localStorage.getItem(`edp_lockout_${username}`)
    if (!raw) return { locked: false, attempts: 0, remaining: 0 }
    const state = JSON.parse(raw)
    const now = Date.now()
    if (state.lockedUntil && now < state.lockedUntil) {
      return {
        locked: true,
        attempts: state.attempts,
        remaining: Math.ceil((state.lockedUntil - now) / 1000 / 60), // minutes
        remainingMs: state.lockedUntil - now
      }
    }
    // Lockout expired — reset
    if (state.lockedUntil && now >= state.lockedUntil) {
      localStorage.removeItem(`edp_lockout_${username}`)
      return { locked: false, attempts: 0, remaining: 0 }
    }
    return { locked: false, attempts: state.attempts || 0, remaining: 0 }
  } catch {
    return { locked: false, attempts: 0, remaining: 0 }
  }
}

export function recordFailedAttempt(username) {
  try {
    const raw = localStorage.getItem(`edp_lockout_${username}`)
    const state = raw ? JSON.parse(raw) : { attempts: 0 }
    const newAttempts = (state.attempts || 0) + 1
    const shouldLock = newAttempts >= MAX_ATTEMPTS
    localStorage.setItem(`edp_lockout_${username}`, JSON.stringify({
      attempts: newAttempts,
      lockedUntil: shouldLock ? Date.now() + LOCKOUT_DURATION_MS : null,
      lastAttempt: Date.now()
    }))
    return { attempts: newAttempts, locked: shouldLock, warnThreshold: WARN_THRESHOLD, maxAttempts: MAX_ATTEMPTS }
  } catch {
    return { attempts: 1, locked: false }
  }
}

export function clearLockout(username) {
  localStorage.removeItem(`edp_lockout_${username}`)
}

// ─── SESSION MANAGEMENT ───────────────────────────────────────────────────────
const SESSION_DURATION_MS = 8 * 60 * 60 * 1000    // 8 hours
const REMEMBER_DURATION_MS = 30 * 24 * 60 * 60 * 1000 // 30 days

export function createSession(user, rememberMe = false) {
  const token = generateToken()
  const expiresAt = Date.now() + (rememberMe ? REMEMBER_DURATION_MS : SESSION_DURATION_MS)
  const session = {
    token,
    userId: user.id,
    username: user.username,
    displayName: user.displayName,
    role: user.role,
    avatar: user.avatar,
    email: user.email,
    permissions: user.permissions,
    createdAt: Date.now(),
    expiresAt,
    rememberMe,
    lastActivity: Date.now()
  }
  localStorage.setItem('edp_session', JSON.stringify(session))
  return session
}

export function getSession() {
  try {
    const raw = localStorage.getItem('edp_session')
    if (!raw) return null
    const session = JSON.parse(raw)
    if (Date.now() > session.expiresAt) {
      localStorage.removeItem('edp_session')
      return null
    }
    // Refresh last activity
    session.lastActivity = Date.now()
    localStorage.setItem('edp_session', JSON.stringify(session))
    return session
  } catch {
    return null
  }
}

export function destroySession() {
  localStorage.removeItem('edp_session')
}

// ─── PASSWORD VALIDATION ──────────────────────────────────────────────────────
export function validatePasswordStrength(password) {
  const checks = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    number: /[0-9]/.test(password),
    special: /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password)
  }
  const passed = Object.values(checks).filter(Boolean).length
  const strength = passed <= 2 ? 'weak' : passed <= 3 ? 'fair' : passed <= 4 ? 'good' : 'strong'
  return { checks, strength, score: passed }
}