import { setConfigSecret } from "../auth";

export function renderLogin(container: HTMLElement): void {
  container.innerHTML = `
    <div class="card login-card">
      <h1>wowauth</h1>
      <p class="hint">Enter the admin config secret to manage apps and users.</p>
      <form id="login-form">
        <input type="password" id="secret" placeholder="Config secret" autocomplete="off" required autofocus />
        <button type="submit">Log in</button>
      </form>
    </div>
  `;

  const form = container.querySelector<HTMLFormElement>("#login-form")!;
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = container.querySelector<HTMLInputElement>("#secret")!;
    const secret = input.value.trim();
    if (!secret) return;
    setConfigSecret(secret);
    location.hash = "#/";
  });
}
