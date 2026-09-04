import { api, type AppStatus, type UserView } from "../api";
import { escapeHtml, reportError } from "../util";

export async function renderHome(container: HTMLElement): Promise<void> {
  container.innerHTML = `<p class="hint">Loading…</p>`;

  let apps: AppStatus[];
  try {
    apps = await api.listApps();
  } catch (err) {
    container.innerHTML = `<div class="card"><p class="error"></p></div>`;
    reportError(err, container.querySelector(".error")!);
    return;
  }

  const usersByApp = await Promise.all(
    apps.map(async (a) => {
      try {
        return { app: a, users: await api.listUsers(a.app_id) };
      } catch {
        return { app: a, users: [] as UserView[] };
      }
    }),
  );

  container.innerHTML = `
    <div class="card">
      <h2>Wizards</h2>
      <p class="hint">Set up a new OAuth connection.</p>
      <ul class="known-apps">
        <li>
          <span>Nmbrs</span>
          <a href="#/nmbrs/new"><button>Start</button></a>
        </li>
      </ul>
    </div>

    <div class="card">
      <h2>Apps</h2>
      ${
        apps.length
          ? `<table>
              <thead>
                <tr><th>Name</th><th>Users</th><th>Active</th><th>Needs reauth</th></tr>
              </thead>
              <tbody>
                ${apps
                  .map(
                    (a) => `
                  <tr class="clickable" data-app-id="${escapeHtml(a.app_id)}">
                    <td>${escapeHtml(a.name)}</td>
                    <td>${a.user_count}</td>
                    <td>${a.active_user_count}</td>
                    <td>${a.needs_reauth_count}</td>
                  </tr>`,
                  )
                  .join("")}
              </tbody>
            </table>`
          : `<p class="hint">No apps registered yet.</p>`
      }
    </div>

    <div class="card">
      <h2>Users</h2>
      ${
        usersByApp.some(({ users }) => users.length)
          ? `<table>
              <thead>
                <tr><th>User ID</th><th>Label</th><th>Scopes</th><th>App</th></tr>
              </thead>
              <tbody>
                ${usersByApp
                  .flatMap(({ app, users }) =>
                    users.map(
                      (u) => `
                    <tr class="clickable" data-app-id="${escapeHtml(app.app_id)}">
                      <td><code>${escapeHtml(u.user_id)}</code></td>
                      <td>${u.label ? escapeHtml(u.label) : '<span class="hint">—</span>'}</td>
                      <td>${escapeHtml(u.scopes || "—")}</td>
                      <td>${escapeHtml(app.name)}</td>
                    </tr>`,
                    ),
                  )
                  .join("")}
              </tbody>
            </table>`
          : `<p class="hint">No users have authorized any app yet.</p>`
      }
    </div>
  `;

  container.querySelectorAll<HTMLTableRowElement>("tr.clickable").forEach((row) => {
    row.addEventListener("click", () => {
      location.hash = `#/apps/${encodeURIComponent(row.dataset.appId!)}`;
    });
  });
}
