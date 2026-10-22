// Nội dung khi chọn một bảng trong nhóm "Database":
// ô SQL (mặc định SELECT * FROM bảng) + bảng dữ liệu phân trang 20 dòng.

import { h } from "../dom.js";
import { createSqlTable } from "../components/sql-table.js";

export function renderDatabasePage(container, table) {
  // Đặt tên bảng trong ngoặc kép vì có bảng trùng từ khóa SQL (ví dụ "order").
  const quoted = `"${table.replaceAll('"', '""')}"`;
  const sqlTable = createSqlTable({ sql: `SELECT * FROM ${quoted}`, label: "Câu SQL truy vấn bảng" });
  container.replaceChildren(
    h("div", { class: "page" },
      h("h2", { class: "page-title" }, "Bảng ", h("code", {}, table)),
      h("p", { class: "muted" }, "Dán câu SQL (một câu SELECT) để lọc dữ liệu hiển thị bên dưới."),
      sqlTable.element,
    ),
  );
}
