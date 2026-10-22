// Popup "Info": cho biết user hiện tại được đọc những bảng/cột nào.
//  - Admin (access = "full"): toàn bộ bảng/cột đọc từ database.
//  - Role nghiệp vụ (access = "reference"): ma trận tham chiếu theo tài liệu policy, CHƯA enforce;
//    quyền thực tế (truy vấn dữ liệu) đang tắt và được hiển thị tách riêng.

import { api } from "../api.js";
import { h, spinner } from "../dom.js";

export async function openInfoDialog() {
  const title = h("strong", {}, "Quyền đọc dữ liệu");
  const body = h("div", { class: "dialog-body" }, spinner(), " Đang tải…");
  const dialog = h("dialog", { class: "dialog" },
    h("div", { class: "dialog-head" },
      title,
      h("button", { class: "icon-button", "aria-label": "Đóng", onclick: () => dialog.close() }, "×")),
    body,
  );
  // Đóng xong thì gỡ khỏi trang để không tích tụ nhiều dialog.
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();

  try {
    const info = await api.info();
    const nodes = info.access === "reference" ? renderReference(info) : renderFull(info);
    if (info.access === "reference") title.textContent = "Thông tin";
    // replaceChildren biến null thành chữ "null" (khác h()), nên bỏ các phần tử rỗng trước.
    body.replaceChildren(...nodes.filter((node) => node !== null && node !== undefined));
  } catch (error) {
    body.replaceChildren(h("div", { class: "error-box" }, error.message));
  }
}

/** Admin: giữ nguyên cách hiển thị cũ. */
function renderFull(info) {
  const columnCount = info.tables.reduce((sum, table) => sum + table.columns.length, 0);
  return [
    h("p", {}, "User ", h("b", {}, info.username), " (role ", h("code", {}, info.role), ") được đọc ",
      h("b", {}, `${info.tables.length} bảng, ${columnCount} cột`), " của database financial."),
    h("p", { class: "muted small" }, info.note),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, h("th", {}, "Bảng"), h("th", {}, "Cột được đọc"), h("th", {}, "Quyền"))),
      h("tbody", {}, info.tables.map((table) => h("tr", {},
        h("td", {}, h("code", {}, table.name)),
        h("td", {}, table.columns.join(", ")),
        h("td", {}, h("span", { class: "badge full" }, table.access))))))),
  ];
}

// Màu badge theo mã quyền tham chiếu.
const BADGE_CLASS = {
  read: "read", partial: "read", aggregate_only: "aggregate",
  aggregate_key: "aggregate", aggregate_dimension: "aggregate", aggregate_measure: "aggregate",
  denied: "denied",
};

/** Role nghiệp vụ: quyền thực tế (tắt) trước, rồi ma trận tham chiếu từng bảng/cột. */
function renderReference(info) {
  const ref = info.reference;
  const label = (code) => ref.access_labels[code] || code;
  const badge = (code) => h("span", { class: `badge ${BADGE_CLASS[code] || ""}` }, label(code));

  return [
    h("p", {}, h("b", {}, info.role_label)),
    h("div", { class: "notice-box", role: "status" },
      h("strong", {}, "Quyền thực tế: truy vấn dữ liệu đang tắt"),
      h("p", {}, info.effective_access.reason)),
    ref.conditions.length
      ? h("div", {},
        h("strong", {}, "Điều kiện chỉ tổng hợp (aggregate-only)"),
        h("ul", { class: "rule-list" }, ref.conditions.map((text) => h("li", {}, text))))
      : null,
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {},
        h("th", {}, "Bảng"), h("th", {}, "Cột"), h("th", {}, "Ý nghĩa"), h("th", {}, "Quyền tham chiếu"))),
      h("tbody", {}, ref.tables.flatMap((table) => [
        h("tr", { class: "table-row" },
          h("td", {}, h("code", {}, table.name)),
          h("td", { colspan: "2" }, table.access === "denied"
            ? "Cấm toàn bảng (mọi cột)"
            : `${table.allowed_columns.length}/${table.columns.length} cột được dùng`),
          h("td", {}, badge(table.access))),
        // Bảng cấm toàn bộ gộp một dòng; bảng còn lại liệt kê từng cột.
        ...(table.access === "denied" ? [] : table.columns.map((column) => h("tr", {},
          h("td", {}),
          h("td", {}, h("code", {}, column.name)),
          h("td", {}, column.meaning),
          h("td", {}, badge(column.access))))),
      ])))),
  ];
}
