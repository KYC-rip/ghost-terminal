/* eslint-disable @typescript-eslint/no-explicit-any */
// src/services/client.ts

interface RequestConfig extends Omit<RequestInit, 'body'> {
  body?: any;
  timeout?: number;
}

export class APIError extends Error {
  status: number;
  data: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

const isOnion = typeof window !== 'undefined' && window.location.hostname.endsWith('.onion');

export const getApiBase = (pathPrefix = 'api') => {
  if (isOnion) {
    return `/${pathPrefix}`;
  }
  return (import.meta as any).env.VITE_API_URL || 'https://api.kyc.rip';
};

export const getMailApiBase = () => {
  if (isOnion) {
    return '/mail-api';
  }
  return (import.meta as any).env.VITE_MAIL_API_URL || 'https://mail-api.kyc.rip';
};

export const getBotApiBase = () => {
  if (isOnion) {
    return '/bot';
  }
  return (import.meta as any).env.VITE_BOT_API_URL || 'https://bot.kyc.rip';
};

type APIType = "api" | "mail-api" | "bot-api";

export async function mailApiClient<T>(endpoint: string, { body, ...customConfig }: RequestConfig = {}, customResponseHandler?: (response: Response) => Promise<T>): Promise<T> {
  return client<T>("mail-api", endpoint, { body, ...customConfig }, customResponseHandler);
}

export async function apiClient<T>(endpoint: string, { body, ...customConfig }: RequestConfig = {}, customResponseHandler?: (response: Response) => Promise<T>): Promise<T> {
  return client<T>("api", endpoint, { body, ...customConfig }, customResponseHandler);
}

export async function botApiClient<T>(endpoint: string, { body, ...customConfig }: RequestConfig = {}, customResponseHandler?: (response: Response) => Promise<T>): Promise<T> {
  return client<T>("bot-api", endpoint, { body, ...customConfig }, customResponseHandler);
}

async function client<T>(type: APIType, endpoint: string, { body, ...customConfig }: RequestConfig = {}, customResponseHandler?: (response: Response) => Promise<T>): Promise<T> {
  const headers = { 'Content-Type': 'application/json' };

  const baseUrls = {
    "api": getApiBase(),
    "mail-api": getMailApiBase(),
    "bot-api": getBotApiBase(),
  }

  const baseUrl = baseUrls[type] || ""; // Default to empty string if type is not found

  const config: RequestConfig = {
    method: body ? 'POST' : 'GET',
    ...customConfig,
    headers: {
      ...headers,
      ...customConfig.headers,
    },
  };

  if (body && typeof body === 'object') {
    config.body = JSON.stringify(body);
  } else if (body && typeof body === 'string') {
    config.body = body;
  }

  const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const url = `${baseUrl}${path}`;

  try {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), customConfig.timeout || 15000);
    config.signal = controller.signal;

    const result = await fetch(url, config);
    clearTimeout(id);

    if (!result.ok) {
      // Surface the server's structured error body ({ error, code, detail })
      // instead of a generic "HTTP Error 500". Fall back to statusText only
      // when the body isn't JSON (e.g. a Cloudflare HTML error page).
      let data: any = undefined;
      let message = result.statusText || `HTTP Error ${result.status}`;
      try {
        data = await result.json();
        message = data?.error || data?.message || data?.detail || message;
      } catch {
        // Non-JSON error body — keep the generic message.
      }
      throw new APIError(message, result.status, data);
    }

    if (customResponseHandler) {
      return await customResponseHandler(result);
    }

    const status = result.status;
    const data = await result.json();

    if (status === 204) return {} as T;

    if (status >= 200 && status < 300) {
      return data as T;
    } else {
      throw new APIError(data?.error || data?.message || `HTTP Error ${status}`, status, data);
    }
  } catch (error: any) {
    if (error instanceof APIError) throw error;
    if (error.name === 'AbortError') throw new APIError('REQUEST_TIMEOUT', 408);
    throw new APIError(error.message || 'NETWORK_ERROR', 0);
  }
}
