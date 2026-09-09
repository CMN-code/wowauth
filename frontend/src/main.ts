import "./style.css";
import { clearConfigSecret, isLoggedIn } from "./auth";
import { renderLogin } from "./views/login";
import { renderHome } from "./views/home";
import { renderAppDetail } from "./views/appDetail";
import { renderNmbrsWizard } from "./views/nmbrsWizard";
import { renderExactWizard } from "./views/exactWizard";

const app = document.getElementById("app")!;
const nav = document.getElementById("nav")!;

function renderNav(): void {
  nav.innerHTML = isLoggedIn()
    ? `<button class="secondary" id="logout">Log out</button>`
    : "";
  nav.querySelector("#logout")?.addEventListener("click", () => {
    clearConfigSecret();
    location.hash = "#/login";
  });
}

function route(): void {
  const hash = location.hash.replace(/^#/, "") || "/";
  renderNav();

  if (!isLoggedIn() && hash !== "/login") {
    location.hash = "#/login";
    return;
  }
  if (isLoggedIn() && hash === "/login") {
    location.hash = "#/";
    return;
  }

  if (hash === "/login") return renderLogin(app);

  if (hash === "/") {
    void renderHome(app);
    return;
  }

  if (hash === "/nmbrs/new") {
    void renderNmbrsWizard(app);
    return;
  }

  if (hash === "/exact/new") {
    void renderExactWizard(app);
    return;
  }

  const detail = hash.match(/^\/apps\/([^/]+)$/);
  if (detail) {
    void renderAppDetail(app, decodeURIComponent(detail[1]));
    return;
  }

  app.innerHTML = `<div class="card"><p>Not found.</p></div>`;
}

window.addEventListener("hashchange", route);
route();
