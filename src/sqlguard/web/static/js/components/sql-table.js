// Component tái sử dụng: ô nhập SQL + bảng dữ liệu phân trang (20 dòng/trang).
// Dùng ở trang Database (SELECT * FROM bảng) và ở trang Query (SQL do agent sinh ra).
// Mọi lần chạy đều gọi POST /api/sql, nên SQL luôn đi qua Security Gate ở backend.

import { api } from "../api.js";
import { h, spinner } from "../dom.js";

/**
 * Tạo component.
 * @param {object} options
 * @param {string} options.sql            câu SQL ban đầu hiển thị trong ô nhập
 * @param {object} [options.initialResult] trang dữ liệu có sẵn (khỏi gọi lại API lần đầu)
 * @param {string} [options.label]        tiêu đề ô SQL
 * @returns {{element: HTMLElement, run: Function}}
 */
export function createSqlTable({ sql, initialResult = null, label = "SQL" }) {
  // Trạng thái nội bộ của component.
  const state = { sql, page: 1, totalPages: 0, loading: false };

  const textarea = h("textarea", { class: "sql-input", rows: "3", spellcheck: "false" });
  textarea.value = sql;
  const runButton = h("button", { class: "btn", onclick: () => run(textarea.value, 1) }, "Chạy SQL");
  const status = h("span", { class: "muted" });
  const errorBox = h("div", { class: "error-box hidden", role: "alert" });
  const tableArea = h("div", { class: "table-wrap" });
  const prevButton = h("button", { class: "btn secondary", onclick: () => run(state.sql, state.page - 1) }, "‹ Trước");
  const nextButton = h("button", { class: "btn secondary", onclick: () => run(state.sql, state.page + 1) }, "Sau ›");
  const pageInfo = h("span", { class: "muted" });
  const pager = h("div", { class: "pager hidden" }, prevButton, pageInfo, nextButton);

  // Ctrl/Cmd + Enter trong ô SQL cũng chạy truy vấn.
  textarea.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) run(textarea.value, 1);
  });

  const element = h("div", { class: "sql-table" },
    h("label", { class: "field-label" }, label),
    textarea,
    h("div", { class: "row" }, runButton, status,
      h("span", { class: "muted small" }, "Ctrl/⌘ + Enter để chạy. Chỉ cho phép một câu SELECT.")),
    errorBox,
    tableArea,
    pager,
  );

  /** Vẽ lại bảng và thanh phân trang từ kết quả API. */
  function render(result) {
    state.sql = result.sql;
    state.page = result.page;
    state.totalPages = result.total_pages;
    if (!result.columns.length) {
      tableArea.replaceChildren(h("p", { class: "muted" }, "Không có cột nào."));
    } else {
      tableArea.replaceChildren(h("table", {},
        h("thead", {}, h("tr", {}, result.columns.map((name) => h("th", {}, name)))),
        h("tbody", {}, result.rows.length
          ? result.rows.map((row) => h("tr", {}, row.map((cell) =>
              h("td", { class: cell === null ? "null" : "" }, cell === null ? "NULL" : cell))))
          : h("tr", {}, h("td", { colspan: String(result.columns.length), class: "muted" }, "0 dòng")))));
    }
    pageInfo.textContent = `Trang ${result.page} / ${result.total_pages} · ${result.total_rows.toLocaleString("vi-VN")} dòng`;
    pager.classList.remove("hidden");
    updateButtons();
  }

  /** Nút Trước/Sau chỉ bấm được khi còn trang và không đang tải. */
  function updateButtons() {
    runButton.disabled = state.loading;
    prevButton.disabled = state.loading || state.page <= 1;
    nextButton.disabled = state.loading || state.page >= state.totalPages;
  }

  /** Bật/tắt trạng thái đang tải. */
  function setLoading(loading) {
    state.loading = loading;
    updateButtons();
    status.replaceChildren(...(loading ? [spinner(), " Đang truy vấn…"] : []));
  }

  /** Chạy SQL và hiển thị trang yêu cầu. */
  async function run(sqlText, page) {
    if (state.loading) return;
    errorBox.classList.add("hidden");
    setLoading(true);
    try {
      const result = await api.runSql(sqlText, page);
      render(result);
    } catch (error) {
      errorBox.textContent = error.message;
      errorBox.classList.remove("hidden");
    } finally {
      setLoading(false);
    }
  }

  // Có kết quả sẵn thì hiển thị ngay, không thì tự chạy SQL ban đầu.
  if (initialResult) render(initialResult);
  else run(sql, 1);

  return { element, run };
}
