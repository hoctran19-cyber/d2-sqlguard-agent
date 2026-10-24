// Sidebar bên trái của trang /home.
//  - Header: tên ứng dụng "SQLGuard".
//  - Thân: item "Query" và nhóm "Database" (tiêu đề, không bấm được) chứa danh sách bảng.
//    Role nghiệp vụ (dataAccess = false) không có Query/Database.
//  - Footer: tên user + role; bấm vào mở menu "Info" và "Logout".

import { api } from "../api.js";
import { h } from "../dom.js";
import { openInfoDialog } from "./info-dialog.js";

/**
 * @param {object} options
 * @param {object} options.user    user hiện tại ({username, role, role_label})
 * @param {string[]} options.tables danh sách bảng của database financial
 * @param {boolean} [options.dataAccess] false: ẩn Query/Database (role nghiệp vụ)
 * @returns {{element: HTMLElement, setActive: Function}}
 */
export function createSidebar({ user, tables, dataAccess = true }) {
  // Mỗi item là một link hash: #/query hoặc #/database/<tên bảng>.
  const links = new Map(); // route -> phần tử <a>, dùng để tô sáng item đang chọn.
  const link = (route, text, extraClass = "") => {
    const anchor = h("a", { href: `#${route}`, class: `nav-item ${extraClass}` }, text);
    links.set(route, anchor);
    return anchor;
  };

  // Menu popup của user, ẩn cho tới khi bấm vào tên.
  const menu = h("div", { class: "user-menu hidden", role: "menu" },
    h("button", { role: "menuitem", onclick: () => { closeMenu(); openInfoDialog(); } }, "Info"),
    h("button", { role: "menuitem", onclick: logout }, "Logout"),
  );
  const userButton = h("button", {
    class: "user-button", "aria-haspopup": "menu", "aria-expanded": "false",
    onclick: (event) => { event.stopPropagation(); toggleMenu(); },
  }, h("span", { class: "avatar" }, user.username.slice(0, 1).toUpperCase()),
  h("span", { class: "user-text" }, user.username,
    user.role_label ? h("span", { class: "user-role" }, user.role_label) : null));

  function toggleMenu() {
    const willOpen = menu.classList.contains("hidden");
    menu.classList.toggle("hidden", !willOpen);
    userButton.setAttribute("aria-expanded", String(willOpen));
  }
  function closeMenu() {
    menu.classList.add("hidden");
    userButton.setAttribute("aria-expanded", "false");
  }
  // Bấm ra ngoài thì đóng menu.
  document.addEventListener("click", (event) => {
    if (!menu.contains(event.target)) closeMenu();
  });

  async function logout() {
    try { await api.logout(); } finally { window.location.href = "/login"; }
  }

  const element = h("aside", { class: "sidebar" },
    h("div", { class: "sidebar-header" }, "SQLGuard"),
    dataAccess
      ? h("nav", { class: "sidebar-nav" },
        link("/query", "Query"),
        user.role === "admin" ? link("/history", "Query History") : null,
        user.role === "admin" && user.lab_enabled ? link("/lab", "Attack Lab") : null,
        h("div", { class: "nav-title" }, "Database"),
        tables.map((table) => link(`/database/${table}`, table, "nav-sub")),
      )
      : h("nav", { class: "sidebar-nav" },
        h("div", { class: "nav-title" }, "Truy vấn dữ liệu đang tắt")),
    h("div", { class: "sidebar-footer" }, userButton, menu),
  );

  /** Tô sáng item tương ứng với route đang hiển thị. */
  function setActive(route) {
    for (const [itemRoute, anchor] of links) {
      anchor.classList.toggle("active", itemRoute === route);
    }
  }

  return { element, setActive };
}
