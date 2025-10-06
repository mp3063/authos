/**
 * Error classes for AuthOS SDK
 */

import type {ErrorContext} from '../types';

export class AuthOSError extends Error {
  public readonly context?: ErrorContext;

  constructor(message: string, context?: ErrorContext) {
    super(message);
    this.name = 'AuthOSError';
    this.context = context;
    Object.setPrototypeOf(this, AuthOSError.prototype);
  }
}

export class NetworkError extends AuthOSError {
  constructor(message: string, context?: ErrorContext) {
    super(message, context);
    this.name = 'NetworkError';
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

export class AuthenticationError extends AuthOSError {
  constructor(message: string, context?: ErrorContext) {
    super(message, context);
    this.name = 'AuthenticationError';
    Object.setPrototypeOf(this, AuthenticationError.prototype);
  }
}

export class AuthorizationError extends AuthOSError {
  constructor(message: string, context?: ErrorContext) {
    super(message, context);
    this.name = 'AuthorizationError';
    Object.setPrototypeOf(this, AuthorizationError.prototype);
  }
}

export class ValidationError extends AuthOSError {
  public readonly errors?: Record<string, string[]>;

  constructor(
    message: string,
    errors?: Record<string, string[]>,
    context?: ErrorContext
  ) {
    super(message, context);
    this.name = 'ValidationError';
    this.errors = errors;
    Object.setPrototypeOf(this, ValidationError.prototype);
  }
}

export class RateLimitError extends AuthOSError {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number, context?: ErrorContext) {
    super(message, context);
    this.name = 'RateLimitError';
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, RateLimitError.prototype);
  }
}

export class TokenExpiredError extends AuthOSError {
  constructor(message: string = 'Access token has expired', context?: ErrorContext) {
    super(message, context);
    this.name = 'TokenExpiredError';
    Object.setPrototypeOf(this, TokenExpiredError.prototype);
  }
}

export class RefreshTokenError extends AuthOSError {
  constructor(message: string = 'Failed to refresh access token', context?: ErrorContext) {
    super(message, context);
    this.name = 'RefreshTokenError';
    Object.setPrototypeOf(this, RefreshTokenError.prototype);
  }
}

export class ConfigurationError extends AuthOSError {
  constructor(message: string) {
    super(message);
    this.name = 'ConfigurationError';
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}

export class NotFoundError extends AuthOSError {
  constructor(message: string, context?: ErrorContext) {
    super(message, context);
    this.name = 'NotFoundError';
    Object.setPrototypeOf(this, NotFoundError.prototype);
  }
}

export class ServerError extends AuthOSError {
  constructor(message: string, context?: ErrorContext) {
    super(message, context);
    this.name = 'ServerError';
    Object.setPrototypeOf(this, ServerError.prototype);
  }
}
