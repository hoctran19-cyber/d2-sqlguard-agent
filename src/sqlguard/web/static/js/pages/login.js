// Trang /login: hai trường username, password và nút Login.

import { api } from "../api.js";
import { h, spinner } from "../dom.js";

export function renderLoginPage(root) {
  const username = h("input", { id: "username", name: "username", autocomplete: "username", required: true });
  const password = h("input", { id: "password", name: "password", type: "password", autocomplete: "current-password", required: true });
  const submit = h("button", { class: "btn wide", type: "submit" }, "Login");
  const errorBox = h("div", { class: "error-box hidden", role: "alert" });

  async function onSubmit(event) {
    event.preventDefault(); // Không reload trang; tự gọi API.
    errorBox.classList.add("hidden");
    submit.disabled = true;
    submit.replaceChildren(spinner(), " Đang đăng nhập…");
    try {
      const user = await api.login(username.value.trim(), password.value);
      // Backend cho biết trang chủ của user: admin -> /home, eval -> /evaluation/.
      window.location.href = user.home;
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.classList.remove("hidden");
      submit.disabled = false;
      submit.replaceChildren("Login");
    }
  }

  root.replaceChildren(h("main", { class: "login-page" },
    h("form", { class: "login-card", onsubmit: onSubmit },
      h("h1", { class: "brand" }, "SQLGuard"),
      h("p", { class: "muted" }, "Đăng nhập để hỏi đáp dữ liệu financial."),
      h("label", { class: "field-label", for: "username" }, "Username"), username,
      h("label", { class: "field-label", for: "password" }, "Password"), password,
      errorBox,
      submit,
    ),
  ));
  username.focus();
}
