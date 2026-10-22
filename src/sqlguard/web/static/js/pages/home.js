// Trang /home: khung chung gồm sidebar bên trái và vùng nội dung bên phải.
// Item đang chọn được lưu trên phần hash của URL:
//   /home#/query            -> trang Query (mặc định, item đầu tiên của sidebar)
//   /home#/database/<bảng>  -> dữ liệu của bảng tương ứng

import { api } from "../api.js";
import { h, spinner } from "../dom.js";
import { createSidebar } from "../components/sidebar.js";
import { renderDatabasePage } from "./database.js";
import { renderQueryPage } from "./query.js";

export async function renderHomePage(root) {
  root.replaceChildren(h("div", { class: "loading-screen" }, spinner(), " Đang tải…"));
  // Lấy thông tin user và danh sách bảng song song.
  const [user, tableList] = await Promise.all([api.me(), api.tables()]);
  const tables = tableList.tables;

  const sidebar = createSidebar({ user, tables });
  const content = h("section", { class: "content" });
  root.replaceChildren(h("div", { class: "layout" }, sidebar.element, content));

  /** Đọc hash hiện tại và render nội dung tương ứng. */
  function route() {
    const hash = decodeURIComponent(window.location.hash.slice(1)); // bỏ dấu "#"
    const table = hash.startsWith("/database/") ? hash.slice("/database/".length) : null;
    if (table && tables.includes(table)) {
      sidebar.setActive(hash);
      renderDatabasePage(content, table);
    } else if (hash === "/query") {
      sidebar.setActive("/query");
      renderQueryPage(content, user);
    } else {
      // Không có hash hoặc hash lạ: chọn item đầu tiên (Query).
      window.location.replace("#/query");
    }
  }

  window.addEventListener("hashchange", route);
  route();
}
