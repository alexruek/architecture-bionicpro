// Фронтенд не работает с токенами: все запросы идут на тот же origin,
// браузер сам прикладывает HttpOnly cookie сессии, выданную bionicpro-auth.

export interface SessionUser {
  sub: string;
  username: string | null;
  email: string | null;
  name: string | null;
  roles: string[];
  identity_provider: string | null;
}

const withSession: RequestInit = { credentials: 'include', cache: 'no-store' };

export async function fetchSession(): Promise<SessionUser | null> {
  const response = await fetch('/auth/session', withSession);
  if (response.status === 401) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Session check failed: ${response.status}`);
  }
  const body = await response.json();
  return body.user as SessionUser;
}

export function login(identityProvider?: string): void {
  const query = identityProvider ? `?idp=${encodeURIComponent(identityProvider)}` : '';
  window.location.assign(`/auth/login${query}`);
}

export async function logout(): Promise<void> {
  await fetch('/auth/logout', { ...withSession, method: 'POST' });
}

export async function apiGet(path: string): Promise<Response> {
  return fetch(`/api${path}`, withSession);
}
