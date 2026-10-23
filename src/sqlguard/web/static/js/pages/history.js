import { api } from "../api.js";
import { h, spinner } from "../dom.js";

const PAGE_SIZE = 20;

export function renderHistoryPage(container) {
  let offset = 0;
  showHistory();

  async function showHistory(errorMessage = null) {
    container.replaceChildren(
      h("div", { class: "page history-page" },
        h("h1", { class: "page-title" }, "Query History"),
        errorMessage
          ? h("div", { class: "error-box", role: "alert" },
            errorMessage,
            h("button", {
              class: "btn secondary",
              onclick: () => showHistory(),
            }, "Thử lại"))
          : h("div", { class: "waiting", role: "status" }, spinner(), " Đang tải lịch sử…")),
    );
    if (errorMessage) return;

    try {
      const page = await api.queryHistory(PAGE_SIZE, offset);
      renderRunList(page);
    } catch (error) {
      showHistory(error.message || "Không thể tải lịch sử Query.");
    }
  }

  function renderRunList(page) {
    const start = page.total ? page.offset + 1 : 0;
    const end = Math.min(page.offset + page.items.length, page.total);
    const cards = page.items.map((run) =>
      h("button", {
        class: "history-card",
        type: "button",
        onclick: () => showRun(run.run_id),
      },
      h("span", { class: "history-run-id" }, run.run_id),
      h("span", {}, `Bắt đầu: ${formatTimestamp(run.started_at)}`),
      h("span", {}, `Trạng thái: ${run.status || "Chưa có terminal event"}`),
      h("span", {}, `Thời lượng: ${formatDuration(run.duration_ms)}`),
      h("span", {}, `Lỗi: ${run.error_category || "—"}`),
      h("span", {}, `${run.event_count} event`)),
    );
    const controls = h("div", { class: "pager" },
      h("button", {
        class: "btn secondary",
        type: "button",
        disabled: page.offset <= 0,
        onclick: () => { offset = Math.max(0, offset - PAGE_SIZE); showHistory(); },
      }, "Trước"),
      h("span", { class: "muted small" }, `${start}–${end} / ${page.total}`),
      h("button", {
        class: "btn secondary",
        type: "button",
        disabled: page.offset + page.items.length >= page.total,
        onclick: () => { offset += PAGE_SIZE; showHistory(); },
      }, "Sau"),
    );
    container.replaceChildren(h("div", { class: "page history-page" },
      h("h1", { class: "page-title" }, "Query History"),
      page.items.length
        ? h("div", { class: "history-list" }, cards)
        : h("p", { class: "muted", role: "status" }, "Chưa có lịch sử Query."),
      controls,
    ));
  }

  async function showRun(runId) {
    container.replaceChildren(h("div", { class: "page history-page" },
      h("button", {
        class: "btn secondary",
        type: "button",
        onclick: () => showHistory(),
      }, "Quay lại danh sách"),
      h("h1", { class: "page-title" }, "Chi tiết lần chạy"),
      h("div", { class: "waiting", role: "status" }, spinner(), " Đang tải events…"),
    ));
    try {
      const detail = await api.queryRunEvents(runId);
      const rows = detail.events.map((event) =>
        h("tr", {},
          h("td", {}, event.event_type),
          h("td", {}, formatTimestamp(event.timestamp)),
          h("td", {}, event.status || "—"),
          h("td", {}, formatDuration(event.duration_ms)),
          h("td", {}, event.error_category || "—")),
      );
      container.replaceChildren(h("div", { class: "page history-page" },
        h("button", {
          class: "btn secondary",
          type: "button",
          onclick: () => showHistory(),
        }, "Quay lại danh sách"),
        h("h1", { class: "page-title" }, "Chi tiết lần chạy"),
        h("p", { class: "muted small history-run-id" }, detail.run_id),
        h("div", { class: "table-wrap" },
          h("table", {},
            h("thead", {}, h("tr", {},
              h("th", {}, "Event"),
              h("th", {}, "Thời điểm"),
              h("th", {}, "Trạng thái"),
              h("th", {}, "Thời lượng"),
              h("th", {}, "Mã lỗi"))),
            h("tbody", {}, rows))),
      ));
    } catch (error) {
      container.replaceChildren(h("div", { class: "page history-page" },
        h("button", {
          class: "btn secondary",
          type: "button",
          onclick: () => showHistory(),
        }, "Quay lại danh sách"),
        h("div", { class: "error-box", role: "alert" },
          error.message || "Không thể tải chi tiết lần chạy."),
      ));
    }
  }
}

function formatTimestamp(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? String(value) : date.toLocaleString();
}

function formatDuration(value) {
  return value === null || value === undefined ? "—" : `${Math.round(value)} ms`;
}
