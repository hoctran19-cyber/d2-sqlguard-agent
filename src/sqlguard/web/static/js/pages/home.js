// Trang /home: khung chung gồm sidebar bên trái và vùng nội dung bên phải.
// Item đang chọn được lưu trên phần hash của URL:
//   /home#/query            -> trang Query (mặc định, item đầu tiên của sidebar)
//   /home#/database/<bảng>  -> dữ liệu của bảng tương ứng
// Role nghiệp vụ (data_access = false) chỉ thấy thông báo truy vấn đang tắt + menu Info/Logout;
// trang không gọi /api/tables, /api/sql, /api/query (server cũng trả 403).

import { api } from "../api.js";
import { h, spinner } from "../dom.js";
import { createSidebar } from "../components/sidebar.js";
import { openInfoDialog } from "../components/info-dialog.js";
import { renderDatabasePage } from "./database.js";
import { renderHistoryPage } from "./history.js";
import { renderQueryPage } from "./query.js";

export async function renderHomePage(root) {
  root.replaceChildren(h("div", { class: "loading-screen" }, spinner(), " Đang tải…"));
  const user = await api.me();
  if (!user.data_access) {
    renderRestrictedHome(root, user);
    return;
  }
  const tables = (await api.tables()).tables;

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
    } else if (hash === "/history" && user.role === "admin") {
      sidebar.setActive("/history");
      renderHistoryPage(content);
    } else {
      // Không có hash hoặc hash lạ: chọn item đầu tiên (Query).
      window.location.replace("#/query");
    }
  }

  window.addEventListener("hashchange", route);
  route();
}

/** /home của role nghiệp vụ: không có Query/Database, không xem trước dữ liệu. */
function renderRestrictedHome(root, user) {
  const sidebar = createSidebar({ user, tables: [], dataAccess: false });
  const content = h("section", { class: "content" },
    h("div", { class: "page" },
      h("h2", { class: "page-title" }, `Xin chào, ${user.username}`),
      h("p", { class: "muted" }, "Role: ", h("b", {}, user.role_label), " (", h("code", {}, user.role), ")"),
      h("div", { class: "notice-box", role: "status" },
        h("strong", {}, "Truy vấn dữ liệu đang tắt"),
        h("p", {}, "Tài khoản role nghiệp vụ chưa được hỏi đáp hoặc xem dữ liệu cho tới khi "
          + "Security Gate thực thi policy Financial. Mục Info chỉ là bảng quyền tham chiếu, "
          + "chưa phải quyền đang có hiệu lực.")),
      h("button", { class: "btn secondary", onclick: () => openInfoDialog() }, "Xem Info quyền tham chiếu"),
    ),
  );
  root.replaceChildren(h("div", { class: "layout" }, sidebar.element, content));
}
