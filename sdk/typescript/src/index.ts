/**
 * AuthOS TypeScript SDK
 * Enterprise authentication service client
 */

export { AuthOSClient } from './client';

// Export types
export type {
  AuthOSConfig,
  TokenResponse,
  TokenInfo,
  User,
  Organization,
  Application,
  AuthenticationLog,
  ApiResponse,
  PaginatedResponse,
  ListOptions,
  LoginCredentials,
  RegisterData,
  CreateUserData,
  UpdateUserData,
  CreateOrganizationData,
  UpdateOrganizationData,
  CreateApplicationData,
  UpdateApplicationData,
  MFASetupResponse,
  SocialProvider,
  PKCEChallenge,
  OAuthState,
  Storage,
  RequestOptions,
  ErrorContext,
} from './types';

// Export errors
export {
  AuthOSError,
  NetworkError,
  AuthenticationError,
  AuthorizationError,
  ValidationError,
  RateLimitError,
  TokenExpiredError,
  RefreshTokenError,
  ConfigurationError,
  NotFoundError,
  ServerError,
} from './errors';

// Export storage adapters
export {
  MemoryStorage,
  BrowserStorage,
  SessionStorageAdapter,
  getDefaultStorage,
} from './utils/storage';

// Export auth utilities
export { TokenManager } from './auth/TokenManager';
export { AuthService } from './auth/AuthService';

// Export API services
export { UsersAPI } from './api/UsersAPI';
export { OrganizationsAPI } from './api/OrganizationsAPI';
export { ApplicationsAPI } from './api/ApplicationsAPI';
