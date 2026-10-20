// Sidebar bên trái của trang /home.
//  - Header: tên ứng dụng "SQLGuard".
//  - Thân: item "Query" và nhóm "Database" (tiêu đề, không bấm được) chứa danh sách bảng.
//  - Footer: tên user; bấm vào mở menu "Info" và "Logout".

import { api } from "../api.js";
import { h } from "../dom.js";
import { openInfoDialog } from "./info-dialog.js";

/**
 * @param {object} options
 * @param {object} options.user    user hiện tại ({username, role})
 * @param {string[]} options.tables danh sách bảng của database financial
 * @returns {{element: HTMLElement, setActive: Function}}
 */
export function createSidebar({ user, tables }) {
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
  }, h("span", { class: "avatar" }, user.username.slice(0, 1).toUpperCase()), user.username);

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
    h("nav", { class: "sidebar-nav" },
      link("/query", "Query"),
      h("div", { class: "nav-title" }, "Database"),
      tables.map((table) => link(`/database/${table}`, table, "nav-sub")),
    ),
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
