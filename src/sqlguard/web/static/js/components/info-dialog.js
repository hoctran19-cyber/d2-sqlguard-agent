// Popup "Info": cho biết user hiện tại được đọc những bảng/cột nào.
// Admin được đọc toàn bộ dữ liệu; khi B chốt role nghiệp vụ, API /api/info trả phạm vi hẹp hơn.

import { api } from "../api.js";
import { h, spinner } from "../dom.js";

export async function openInfoDialog() {
  const body = h("div", { class: "dialog-body" }, spinner(), " Đang tải…");
  const dialog = h("dialog", { class: "dialog" },
    h("div", { class: "dialog-head" },
      h("strong", {}, "Quyền đọc dữ liệu"),
      h("button", { class: "icon-button", "aria-label": "Đóng", onclick: () => dialog.close() }, "×")),
    body,
  );
  // Đóng xong thì gỡ khỏi trang để không tích tụ nhiều dialog.
  dialog.addEventListener("close", () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();

  try {
    const info = await api.info();
    const columnCount = info.tables.reduce((sum, table) => sum + table.columns.length, 0);
    body.replaceChildren(
      h("p", {}, "User ", h("b", {}, info.username), " (role ", h("code", {}, info.role), ") được đọc ",
        h("b", {}, `${info.tables.length} bảng, ${columnCount} cột`), " của database financial."),
      h("p", { class: "muted small" }, info.note),
      h("div", { class: "table-wrap" }, h("table", {},
        h("thead", {}, h("tr", {}, h("th", {}, "Bảng"), h("th", {}, "Cột được đọc"), h("th", {}, "Quyền"))),
        h("tbody", {}, info.tables.map((table) => h("tr", {},
          h("td", {}, h("code", {}, table.name)),
          h("td", {}, table.columns.join(", ")),
          h("td", {}, h("span", { class: "badge full" }, table.access))))))),
    );
  } catch (error) {
    body.replaceChildren(h("div", { class: "error-box" }, error.message));
  }
}
