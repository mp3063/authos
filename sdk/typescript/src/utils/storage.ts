/**
 * Storage adapters for token persistence
 */

import type {Storage} from '../types';

/**
 * In-memory storage (tokens lost on page refresh)
 */
export class MemoryStorage implements Storage {
  private store = new Map<string, string>();

  getItem(key: string): string | null {
    return this.store.get(key) ?? null;
  }

  setItem(key: string, value: string): void {
    this.store.set(key, value);
  }

  removeItem(key: string): void {
    this.store.delete(key);
  }

  clear(): void {
    this.store.clear();
  }
}

/**
 * LocalStorage adapter (browser only)
 */
export class BrowserStorage implements Storage {
  constructor(private prefix: string = 'authos_') {
    if (typeof window === 'undefined' || !window.localStorage) {
      throw new Error('LocalStorage is not available');
    }
  }

  getItem(key: string): string | null {
    return localStorage.getItem(this.prefix + key);
  }

  setItem(key: string, value: string): void {
    localStorage.setItem(this.prefix + key, value);
  }

  removeItem(key: string): void {
    localStorage.removeItem(this.prefix + key);
  }

  clear(): void {
    const keys = Object.keys(localStorage);
    keys.forEach((key) => {
      if (key.startsWith(this.prefix)) {
        localStorage.removeItem(key);
      }
    });
  }
}

/**
 * SessionStorage adapter (browser only, cleared on tab close)
 */
export class SessionStorageAdapter implements Storage {
  constructor(private prefix: string = 'authos_') {
    if (typeof window === 'undefined' || !window.sessionStorage) {
      throw new Error('SessionStorage is not available');
    }
  }

  getItem(key: string): string | null {
    return sessionStorage.getItem(this.prefix + key);
  }

  setItem(key: string, value: string): void {
    sessionStorage.setItem(this.prefix + key, value);
  }

  removeItem(key: string): void {
    sessionStorage.removeItem(this.prefix + key);
  }

  clear(): void {
    const keys = Object.keys(sessionStorage);
    keys.forEach((key) => {
      if (key.startsWith(this.prefix)) {
        sessionStorage.removeItem(key);
      }
    });
  }
}

/**
 * Get default storage based on environment
 */
export function getDefaultStorage(): Storage {
  if (typeof window !== 'undefined' && window.localStorage) {
    return new BrowserStorage();
  }
  return new MemoryStorage();
}
