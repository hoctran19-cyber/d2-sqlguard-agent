// Điểm vào của giao diện: chọn trang cần render theo đường dẫn URL.
// Việc chuyển hướng theo đăng nhập (/ -> /login hoặc /home, chặn /evaluation) do backend làm.

import { h } from "./dom.js";
import { renderHomePage } from "./pages/home.js";
import { renderLoginPage } from "./pages/login.js";

const root = document.getElementById("app");

async function start() {
  const path = window.location.pathname;
  try {
    if (path === "/login") renderLoginPage(root);
    else if (path === "/home") await renderHomePage(root);
    else window.location.replace("/"); // Đường dẫn lạ: để backend quyết định trang đích.
  } catch (error) {
    root.replaceChildren(h("div", { class: "error-box page" }, "Không tải được trang: ", error.message));
  }
}

start();
