// Trang Query — giao diện chính, gồm 3 trạng thái:
//   Phase 1 "ask":     chưa có dữ liệu, hiện "Ask me, {username}" và ô nhập câu hỏi.
//   Phase chờ "waiting": đã gửi câu hỏi, chờ hệ thống trả lời.
//   Phase 2 "answer":  hộp trạng thái (full/partial/refusal) + câu SQL + bảng dữ liệu.

import { api } from "../api.js";
import { h, spinner } from "../dom.js";
import { createSqlTable } from "../components/sql-table.js";
import { injectionNotice, labRevisionsLine } from "../components/injection-notice.js";
import { createWorkflowVisualizer } from "../components/workflow-visualizer.js";

// Nhãn và màu cho từng loại kết quả trả về từ backend.
const STATUS_LABELS = {
  full: { title: "Full answer", text: "Trả lời đầy đủ" },
  partial: { title: "Partial answer", text: "Trả lời một phần" },
  refused: { title: "Refusal answer", text: "Từ chối trả lời" },
  failed: { title: "No answer", text: "Không có câu trả lời" },
};

// Giữ câu trả lời gần nhất để khi chuyển sang Database rồi quay lại vẫn còn.
let lastAnswer = null;
let activeEventSource = null;
let playbackSettings = { mode: "step", delay: 800, detailLevel: "detailed" };

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
  const modeSelect = h("select", { "aria-label": "Playback mode before submit" },
    h("option", { value: "step" }, "Step-by-step"),
    h("option", { value: "auto" }, "Auto-play"),
    h("option", { value: "fast" }, "Fast mode"),
  );
  modeSelect.value = playbackSettings.mode;
  modeSelect.addEventListener("change", () => {
    playbackSettings = { ...playbackSettings, mode: modeSelect.value };
  });
  const delayInput = h("input", {
    type: "range",
    min: "0",
    max: "3000",
    step: "100",
    value: String(playbackSettings.delay),
    "aria-label": "Auto-play delay before submit in milliseconds",
  });
  const delayValue = h("span", { class: "workflow-delay-value" }, `${playbackSettings.delay} ms`);
  delayInput.addEventListener("input", () => {
    playbackSettings = { ...playbackSettings, delay: Number(delayInput.value) };
    delayValue.textContent = `${delayInput.value} ms`;
  });
  const detailSelect = h("select", { "aria-label": "Information level before submit" },
    h("option", { value: "basic" }, "Basic"),
    h("option", { value: "detailed" }, "Detailed"),
  );
  detailSelect.value = playbackSettings.detailLevel;
  detailSelect.addEventListener("change", () => {
    playbackSettings = { ...playbackSettings, detailLevel: detailSelect.value };
  });
  const sendButton = h("button", { class: "btn", onclick: () => send(input.value) }, "Gửi");
  // Vùng câu hỏi mẫu: tải từ backend (planner demo chưa có LLM chỉ hiểu các câu này).
  const samples = h("div", { class: "samples" });
  api.samples().then((data) => samples.replaceChildren(
    h("p", { class: "muted small" },
      data.mode === "business_sqlite"
        ? `Financial · role ${data.role} · policy ${data.policy} · planner ${data.planner} (model ${data.model}) — câu hỏi gợi ý:`
        : data.mode === "synthetic_sqlite"
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
    h("div", { class: "ask-box" },
      input,
      h("div", { class: "workflow-controls ask-playback-controls" },
        h("label", {}, "Playback ", modeSelect),
        h("label", { class: "workflow-delay" },
          "Delay ", delayInput, delayValue),
        h("label", {}, "Information ", detailSelect),
      ),
      h("p", { class: "muted small ask-playback-note" },
        "Playback delay only affects how events are presented; it does not slow agent execution."),
      h("div", { class: "ask-actions" }, sendButton)),
    samples,
  ));
  input.focus();
}

/** Phase chờ: gửi câu hỏi tới backend và hiện trạng thái đang xử lý. */
async function ask(container, user, question) {
  if (activeEventSource) activeEventSource.close();
  const selectedPlayback = { ...playbackSettings };
  const runId = crypto.randomUUID();
  const visualizer = createWorkflowVisualizer(
    { question, run_id: runId, events: [] },
    {
      live: true,
      playback: selectedPlayback,
      autoStart: selectedPlayback.mode !== "step",
    },
  );
  let started = false;
  let receivedLiveEvents = 0;
  const receivedSequences = new Set();
  let finalized = false;
  const source = new EventSource(`/api/query/stream/${encodeURIComponent(runId)}`);
  activeEventSource = source;

  container.replaceChildren(h("div", { class: "page" },
    h("div", { class: "row space-between" },
      h("div", { class: "question-bubble" }, question),
      h("span", { class: "waiting", role: "status" }, spinner(), " Đang chạy agent…")),
    visualizer.element,
  ));

  const startRequest = async () => {
    if (started) return;
    started = true;
    let answer;
    try {
      answer = await api.ask(question, runId);
    } catch (error) {
      answer = {
        question,
        run_id: runId,
        status: "failed",
        execution_status: "failed",
        reason: error.message,
        sql: null,
        result: null,
        omitted_fields: [],
        events: [],
      };
      source.close();
      visualizer.setConnectionState("error", "Query request failed.");
    }
    if (finalized) return;
    finalized = true;
    const traceEvents = Array.isArray(answer.trace_events) ? answer.trace_events : [];
    if (traceEvents.length) {
      let recovered = 0;
      for (const event of traceEvents) {
        const sequence = event.stream_sequence ?? event.sequence;
        if (sequence && receivedSequences.has(sequence)) continue;
        visualizer.appendLiveEvent({ ...event, stream_sequence: sequence });
        if (sequence) receivedSequences.add(sequence);
        recovered += 1;
      }
      if (!receivedLiveEvents && traceEvents.length) {
        visualizer.setConnectionState(
          "playback",
          "Live stream unavailable; showing events collected by the completed run.",
        );
      } else if (recovered) {
        visualizer.setConnectionState(
          "completed",
          `${recovered} missing event(s) restored from the completed run trace.`,
        );
      }
    } else if (!receivedLiveEvents && Array.isArray(answer.events)) {
      for (const event of answer.events) visualizer.appendLiveEvent(event);
      if (answer.events.length) {
        visualizer.setConnectionState(
          "playback",
          "Live stream unavailable; showing metadata collected by the completed run.",
        );
      }
    }
    lastAnswer = answer;
    visualizer.setTraceAssessment(answer.trace_assessment);
    visualizer.updateAnswer(answer);
    showAnswer(container, user, answer, visualizer);
  };

  source.onopen = () => {
    visualizer.setConnectionState("connected", "connected");
    startRequest();
  };
  source.addEventListener("agent_event", (message) => {
    try {
      const event = JSON.parse(message.data);
      event.stream_sequence = Number(message.lastEventId);
      if (event.stream_sequence) receivedSequences.add(event.stream_sequence);
      receivedLiveEvents += 1;
      visualizer.appendLiveEvent(event);
    } catch {
      visualizer.setConnectionState("error", "Received an invalid live event.");
    }
  });
  source.addEventListener("stream_gap", () => {
    visualizer.setConnectionState("reconnecting", "some early events are outside the replay window.");
  });
  source.addEventListener("stream_complete", (message) => {
    source.close();
    try {
      const completion = JSON.parse(message.data);
      visualizer.setTraceAssessment(completion.trace_assessment);
    } catch {
      visualizer.setTraceAssessment(null);
    }
    visualizer.setConnectionState("completed", "run event stream completed");
  });
  source.onerror = () => {
    if (!started) startRequest();
    if (source.readyState === EventSource.CLOSED) {
      visualizer.setConnectionState("error", "stream unavailable; reconnect was not possible.");
    } else {
      visualizer.setConnectionState("reconnecting", "connection interrupted; replay is being resumed.");
    }
  };
}

/** Phase 2: hiển thị kết quả. */
function showAnswer(container, user, answer, visualizer = null) {
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
    answer.run_id ? h("details", { class: "query-run-details" },
      h("summary", { class: "muted small" }, "Run details"),
      h("p", { class: "muted small" },
        `Run ID: ${answer.run_id} · planner ${answer.planner}${answer.model ? ` · model ${answer.model}` : ""} · ${Math.round(answer.duration_ms)} ms`)) : null,
    answer.execution_status
      ? h("p", { class: "muted small" },
        `Backend: ${answer.backend === "business_sqlite" ? `SQLite Financial · role ${answer.role} · policy ${answer.policy_version}` : "SQLite tổng hợp"} · execution: ${answer.execution_status} · ${answer.row_count} dòng${answer.truncated ? " (đã giới hạn kết quả)" : ""}`)
      : null,
  );

  // Kết quả của runtime policy chỉ để hiển thị; không gửi lại qua /api/sql.
  const synthetic = answer.backend === "synthetic_sqlite" || answer.backend === "business_sqlite";
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
        onclick: () => {
          if (activeEventSource) activeEventSource.close();
          lastAnswer = null;
          showAsk(container, user);
        },
      }, "Đặt câu hỏi mới")),
    statusBox,
    answer.possible_injection ? injectionNotice() : null,
    labRevisionsLine(answer.lab_revisions),
    gateArea,
    sqlArea,
    resultArea,
    visualizer ? visualizer.element : createWorkflowVisualizer(answer).element,
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
