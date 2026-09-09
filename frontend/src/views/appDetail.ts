import { api, type AppView, type AppStatus, type UserView } from "../api";
import { escapeHtml, reportError } from "../util";

export async function renderAppDetail(container: HTMLElement, appId: string): Promise<void> {
  container.innerHTML = `<p class="hint">Loading…</p>`;
  try {
    const status = await api.getAppStatus(appId);
    // There's no GET-by-id endpoint for the full app record, only by-name,
    // so fetch that too to display the rest of the fields.
    const app = await api.getAppByName(status.name);
    renderLoaded(container, app, status);
  } catch (err) {
    container.innerHTML = `<div class="card"><p class="error"></p></div>`;
    reportError(err, container.querySelector(".error")!);
  }
}

function renderLoaded(container: HTMLElement, app: AppView, status: AppStatus): void {
  container.innerHTML = `
    <div class="card">
      <h2>${escapeHtml(app.name)}</h2>
      <p class="hint"><code>${escapeHtml(app.id)}</code></p>
      <div class="stats">
        <div class="stat"><strong>${status.user_count}</strong><span>users</span></div>
        <div class="stat"><strong>${status.active_user_count}</strong><span>active</span></div>
        <div class="stat"><strong>${status.needs_reauth_count}</strong><span>needs reauth</span></div>
      </div>
    </div>

    <div class="card">
      <h3>App details</h3>
      <table>
        <tbody>
          <tr><th>Client ID</th><td><code>${escapeHtml(app.client_id)}</code></td></tr>
          <tr><th>Auth URL</th><td><code>${escapeHtml(app.auth_url)}</code></td></tr>
          <tr><th>Token URL</th><td><code>${escapeHtml(app.token_url)}</code></td></tr>
          <tr><th>Redirect URL</th><td><code>${escapeHtml(app.redirect_url)}</code></td></tr>
          <tr><th>Allowed redirect URIs</th><td>${app.allowed_redirect_uris.length ? app.allowed_redirect_uris.map((u) => `<code>${escapeHtml(u)}</code>`).join("<br />") : '<span class="hint">—</span>'}</td></tr>
          <tr><th>Scopes</th><td>${escapeHtml(app.scopes || "—")}</td></tr>
          <tr><th>Token auth method</th><td>${escapeHtml(app.token_auth_method)}</td></tr>
          <tr><th>Public key</th><td><code>${escapeHtml(app.public_key)}</code></td></tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <h3>Users</h3>
      <div id="users-holder"><p class="hint">Loading users…</p></div>
    </div>
  `;

  loadUsers(container, app.id);
}

async function loadUsers(container: HTMLElement, appId: string): Promise<void> {
  const holder = container.querySelector<HTMLElement>("#users-holder")!;
  try {
    const users = await api.listUsers(appId);
    renderUsers(holder, appId, users);
  } catch (err) {
    holder.innerHTML = `<p class="error"></p>`;
    reportError(err, holder.querySelector(".error")!);
  }
}

function renderUsers(holder: HTMLElement, appId: string, users: UserView[]): void {
  if (users.length === 0) {
    holder.innerHTML = `<p class="hint">No users have authorized this app yet.</p>`;
    return;
  }

  holder.innerHTML = `
    <table>
      <thead>
        <tr><th>User ID</th><th>Label</th><th>Scopes</th><th>Status</th></tr>
      </thead>
      <tbody>
        ${users
          .map(
            (u) => `
          <tr data-user-id="${escapeHtml(u.user_id)}">
            <td><code>${escapeHtml(u.user_id)}</code></td>
            <td>${u.label ? escapeHtml(u.label) : "<span class=\"hint\">—</span>"}</td>
            <td>${escapeHtml(u.scopes || "—")}</td>
            <td class="status-cell"><button class="secondary check-status">Check</button></td>
          </tr>`,
          )
          .join("")}
      </tbody>
    </table>
  `;

  holder.querySelectorAll<HTMLTableRowElement>("tr[data-user-id]").forEach((row) => {
    const userId = row.dataset.userId!;

    row.querySelector(".check-status")!.addEventListener("click", async () => {
      const cell = row.querySelector(".status-cell")!;
      cell.innerHTML = `<span class="hint">checking…</span>`;
      try {
        const s = await api.getUserStatus(appId, userId);
        const expiry = s.expires_at ? ` <span class="hint">${escapeHtml(new Date(s.expires_at).toLocaleString())}</span>` : "";
        cell.innerHTML = `<span class="pill ${s.status === "active" ? "active" : "expired"}">${escapeHtml(s.status)}</span>${expiry}`;
      } catch (err) {
        cell.innerHTML = `<span class="error"></span>`;
        reportError(err, cell.querySelector(".error")!);
      }
    });
  });
}
