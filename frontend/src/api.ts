import type { components } from "./api-types";
import { getConfigSecret } from "./auth";

export type AppView = components["schemas"]["AppView"];
export type AppStatus = components["schemas"]["AppStatus"];
export type CreateAppRequest = components["schemas"]["CreateAppRequest"];
export type UpdateAppRequest = components["schemas"]["UpdateAppRequest"];
export type UserView = components["schemas"]["UserView"];
export type UserStatus = components["schemas"]["UserStatus"];

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set("Authorization", `Bearer ${getConfigSecret() ?? ""}`);
  if (init.body) headers.set("Content-Type", "application/json; charset=utf-8");

  const res = await fetch(path, { ...init, headers });
  const text = await res.text();

  if (!res.ok) {
    throw new ApiError(res.status, text || res.statusText);
  }
  return text ? (JSON.parse(text) as T) : (undefined as T);
}

const encode = (s: string) => encodeURIComponent(s);

export const api = {
  listApps: () => request<AppStatus[]>("/apps"),

  createApp: (body: CreateAppRequest) =>
    request<AppView>("/apps", { method: "POST", body: JSON.stringify(body) }),

  updateApp: (appId: string, body: UpdateAppRequest) =>
    request<AppView>(`/apps/${encode(appId)}`, { method: "PATCH", body: JSON.stringify(body) }),

  getAppByName: (name: string) => request<AppView>(`/apps/by-name/${encode(name)}`),

  getAppStatus: (appId: string) => request<AppStatus>(`/apps/${encode(appId)}/status`),

  listUsers: (appId: string) => request<UserView[]>(`/apps/${encode(appId)}/users`),

  getUserStatus: (appId: string, userId: string) =>
    request<UserStatus>(`/apps/${encode(appId)}/users/${encode(userId)}/status`),
};
