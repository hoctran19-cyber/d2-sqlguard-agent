// Trang Query — giao diện chính, gồm 3 trạng thái:
//   Phase 1 "ask":     chưa có dữ liệu, hiện "Ask me, {username}" và ô nhập câu hỏi.
//   Phase chờ "waiting": đã gửi câu hỏi, chờ hệ thống trả lời.
//   Phase 2 "answer":  hộp trạng thái (full/partial/refusal) + câu SQL + bảng dữ liệu.

import { api } from "../api.js";
import { h, spinner } from "../dom.js";
import { createSqlTable } from "../components/sql-table.js";

// Nhãn và màu cho từng loại kết quả trả về từ backend.
const STATUS_LABELS = {
  full: { title: "Full answer", text: "Trả lời đầy đủ" },
  partial: { title: "Partial answer", text: "Trả lời một phần" },
  refused: { title: "Refusal answer", text: "Từ chối trả lời" },
  failed: { title: "No answer", text: "Không có câu trả lời" },
};

// Giữ câu trả lời gần nhất để khi chuyển sang Database rồi quay lại vẫn còn.
let lastAnswer = null;

export function renderQueryPage(container, user) {
  if (lastAnswer) showAnswer(container, user, lastAnswer);
  else showAsk(container, user);
}

/** Phase 1: ô nhập câu hỏi. */
function showAsk(container, user, previousQuestion = "") {
  const input = h("textarea", {
    class: "ask-input", rows: "3", placeholder: "Đặt câu hỏi về dữ liệu…", "aria-label": "Câu hỏi",
  });
  input.value = previousQuestion;
  const sendButton = h("button", { class: "btn", onclick: () => send(input.value) }, "Gửi");
  // Vùng câu hỏi mẫu: tải từ backend (planner demo chưa có LLM chỉ hiểu các câu này).
  const samples = h("div", { class: "samples" });
  api.samples().then((data) => samples.replaceChildren(
    h("p", { class: "muted small" },
      data.mode === "synthetic_sqlite"
        ? `SQLite tổng hợp · planner ${data.planner} (model ${data.model}) — câu hỏi gợi ý:`
        : `Planner ${data.planner} (chưa tích hợp LLM) chỉ hiểu các câu hỏi mẫu dưới đây:`),
    // replaceChildren không tự trải mảng nên dùng "..." để thêm từng nút.
    ...data.questions.map((question) =>
      h("button", { class: "chip", onclick: () => send(question) }, question)),
  )).catch(() => {});
  // Enter để gửi, Shift + Enter để xuống dòng.
  input.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      send(input.value);
    }
  });

  function send(question) {
    if (question.trim()) ask(container, user, question.trim());
  }

  container.replaceChildren(h("div", { class: "page ask-page" },
    h("h1", { class: "ask-title" }, `Ask me, ${user.username}`),
    h("div", { class: "ask-box" }, input, h("div", { class: "ask-actions" }, sendButton)),
    samples,
  ));
  input.focus();
}

/** Phase chờ: gửi câu hỏi tới backend và hiện trạng thái đang xử lý. */
async function ask(container, user, question) {
  container.replaceChildren(h("div", { class: "page" },
    h("div", { class: "question-bubble" }, question),
    h("div", { class: "waiting", role: "status" }, spinner(), " SQLGuard đang xử lý câu hỏi…"),
  ));
  let answer;
  try {
    answer = await api.ask(question);
  } catch (error) {
    // Lỗi hạ tầng (mất kết nối, 503...) cũng hiển thị như một câu trả lời thất bại.
    answer = { question, status: "failed", reason: error.message, sql: null, result: null, omitted_fields: [] };
  }
  lastAnswer = answer;
  showAnswer(container, user, answer);
}

/** Phase 2: hiển thị kết quả. */
function showAnswer(container, user, answer) {
  const label = STATUS_LABELS[answer.status] || STATUS_LABELS.failed;

  // Hộp trạng thái: loại câu trả lời + nguyên nhân (nếu từ chối hoặc trả lời một phần).
  const statusBox = h("div", { class: `status-box ${answer.status}`, role: "status" },
    h("div", { class: "status-head" },
      h("span", { class: `badge ${answer.status}` }, label.title),
      h("strong", {}, label.text)),
    h("p", {}, answer.reason),
    answer.omitted_fields && answer.omitted_fields.length
      ? h("p", { class: "muted" }, "Phần bị bỏ: ", answer.omitted_fields.join(", "))
      : null,
    answer.run_id ? h("p", { class: "muted small" },
      `Run ${answer.run_id} · planner ${answer.planner}${answer.model ? ` · model ${answer.model}` : ""} · ${Math.round(answer.duration_ms)} ms`) : null,
    answer.execution_status
      ? h("p", { class: "muted small" },
        `Backend: SQLite tổng hợp · execution: ${answer.execution_status} · ${answer.row_count} dòng${answer.truncated ? " (đã giới hạn kết quả)" : ""}`)
      : null,
  );

  const synthetic = answer.backend === "synthetic_sqlite";
  const gateArea = answer.gate
    ? h("div", { class: `gate-result ${answer.gate.status === "ALLOW" ? "allowed" : "blocked"}` },
      h("strong", {}, `Security Gate: ${answer.gate.status}`),
      h("span", {}, answer.gate.reason))
    : null;
  let sqlArea = null;
  let resultArea = null;
  if (answer.sql && synthetic) {
    sqlArea = h("div", {},
      h("label", { class: "field-label" }, "SQL do planner đề xuất"),
      h("pre", { class: "sql-box" }, answer.sql));
    if (answer.result) resultArea = renderStaticResult(answer.result);
  } else if (answer.result) {
    resultArea = createSqlTable({
      sql: answer.sql, initialResult: answer.result, label: "Câu SQL được sinh ra",
    }).element;
  } else if (answer.sql) {
    sqlArea = h("div", {},
      h("label", { class: "field-label" }, "Câu SQL được sinh ra (không được thực thi)"),
      h("pre", { class: "sql-box" }, answer.sql));
  }

  container.replaceChildren(h("div", { class: "page" },
    h("div", { class: "row space-between" },
      h("div", { class: "question-bubble" }, answer.question),
      h("button", {
        class: "btn secondary",
        onclick: () => { lastAnswer = null; showAsk(container, user); },
      }, "Đặt câu hỏi mới")),
    statusBox,
    gateArea,
    sqlArea,
    resultArea,
  ));
}

/** Synthetic runtime results are display-only; never route them to the legacy /api/sql API. */
function renderStaticResult(result) {
  const rows = result.rows.length
    ? result.rows.map((row) => h("tr", {}, row.map((cell) =>
      h("td", { class: cell === null ? "null" : "" }, cell === null ? "NULL" : cell))))
    : [h("tr", {}, h("td", {
      colspan: String(result.columns.length || 1), class: "muted",
    }, "0 dòng"))];
  return h("section", {},
    h("label", { class: "field-label" }, "Kết quả SQLite (chỉ đọc)"),
    h("div", { class: "table-wrap" },
      h("table", {},
        h("thead", {}, h("tr", {}, result.columns.map((name) => h("th", {}, name)))),
        h("tbody", {}, rows))),
  );
}
