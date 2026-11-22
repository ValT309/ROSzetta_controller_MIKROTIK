import { create } from 'zustand';
import { persist } from 'zustand/middleware';

interface AuthState {
  sessionEpoch: number;
  accessToken: string | null;
  refreshToken: string | null;
  email: string | null;
  setTokens: (a: string, r: string, email?: string) => void;
  logout: () => void;
}

export const useAuth = create<AuthState>()(
  persist(
    (set) => ({
      sessionEpoch: 0,
      accessToken: null,
      refreshToken: null,
      email: null,
      setTokens: (a, r, email) => set((s) => ({ accessToken: a, refreshToken: r, email: email ?? null, sessionEpoch: s.sessionEpoch + 1 })),
      logout: () => set((s) => ({ accessToken: null, refreshToken: null, email: null, sessionEpoch: s.sessionEpoch + 1 })),
    }),
    { name: 'mcc-auth' },
  ),
);
