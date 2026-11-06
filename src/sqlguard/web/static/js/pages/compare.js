// Trang so sánh Naive agent / SQLGuard (chỉ admin, chỉ khi server bật SQLGUARD_NAIVE_DEMO=1).
// Cùng câu hỏi, cùng role, cùng bản sao lab. Cột trái là cấu hình CỐ TÌNH không an toàn để
// seminar thấy biểu hiện của prompt injection; cột phải là SQLGuard như bình thường.
// Payload được cài qua chính route Attack Lab (có audit, chỉ ghi bản sao lab).

import { api } from "../api.js";
import { h, spinner } from "../dom.js";
import { injectionNotice, labRevisionsLine } from "../components/injection-notice.js";
import { renderNaiveMarkdown } from "../components/naive-markdown.js";

export async function renderComparePage(container) {
  container.replaceChildren(h("div", { class: "page" }, spinner(), " Đang tải…"));
  let config;
  try {
    config = await api.compareScenarios();
  } catch (error) {
    container.replaceChildren(h("div", { class: "page" },
      h("h1", { class: "page-title" }, "Naive vs SQLGuard"),
      h("div", { class: "error-box", role: "alert" }, error.message)));
    return;
  }

  const scripted = config.naive_model === "scripted";
  const question = h("textarea", {
    class: "sql-input", rows: "2", spellcheck: "false", "aria-label": "Câu hỏi",
  });
  const role = h("select", { class: "lab-target", "aria-label": "Role" },
    config.roles.map((name) => h("option", { value: name, selected: name === "operator" }, name)));
  const runButton = h("button", { class: "btn", onclick: run }, "Chạy cả hai");
  const status = h("span", { class: "muted small", role: "status" });
  const message = h("div", { class: "hidden", role: "status" });
  const results = h("div", { class: "compare-results" });
  let busy = false;

  question.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) run();
  });

  container.replaceChildren(h("div", { class: "page compare-page" },
    h("h1", { class: "page-title" }, "Naive agent vs SQLGuard"),
    h("div", { class: "danger-box", role: "note" },
      h("strong", {}, "CẤU HÌNH CỐ TÌNH KHÔNG AN TOÀN, chỉ dùng cho seminar"),
      h("p", {}, "Cột trái: quyền chỉ nằm trong prompt, model đọc nguyên văn dữ liệu của bản sao "
        + "lab và tự viết câu trả lời; trang này render câu trả lời đó, kể cả ảnh từ URL ngoài. "
        + (scripted ? "" : "Dữ liệu synthetic của bản sao lab được gửi tới Google Gemini."))),
    h("p", {}, "Model của naive agent: ",
      h("span", { class: scripted ? "badge partial" : "badge" },
        scripted ? "Model giả lập bị chiếm (scripted), không phải Gemini" : "Gemini (model thật)")),
    h("h2", { class: "section-title" }, "Kịch bản"),
    h("div", { class: "scenario-grid" }, config.scenarios.map(scenarioCard)),
    message,
    h("h2", { class: "section-title" }, "Câu hỏi"),
    question,
    h("div", { class: "row" }, h("label", { class: "muted small" }, "Role "), role, runButton, status),
    results,
  ));

  function show(text, kind) {
    message.className = kind === "error" ? "error-box" : "ok-box";
    message.textContent = text;
  }

  function scenarioCard(scenario) {
    const actions = [
      h("button", { class: "btn secondary", onclick: () => { question.value = scenario.question; question.focus(); } },
        "Dùng câu hỏi"),
    ];
    if (scenario.target) {
      actions.push(
        h("button", { class: "btn secondary", disabled: !scenario.installable,
          onclick: () => install(scenario) }, `Cài payload`),
        h("button", { class: "btn secondary", disabled: !scenario.installable,
          onclick: () => restore(scenario.target) }, "Restore"),
      );
    }
    return h("div", { class: "scenario-card" },
      h("div", { class: "row" },
        h("strong", {}, scenario.id),
        h("span", { class: scenario.kind === "direct" ? "badge" : "badge partial" }, scenario.kind),
        scenario.owasp.map((tag) => h("span", { class: "badge" }, tag))),
      h("p", { class: "scenario-title" }, scenario.title),
      h("p", { class: "muted small" }, "Câu hỏi: ", scenario.question),
      scenario.payload
        ? h("details", {}, h("summary", { class: "small" }, `Payload (${scenario.target})`),
          h("pre", { class: "sql-box wrap" }, scenario.payload))
        : h("p", { class: "muted small" }, "Direct injection: payload nằm ngay trong câu hỏi."),
      scenario.target && !scenario.installable
        ? h("p", { class: "muted small" },
          `Lab chưa có target ${scenario.target} (thêm vào SQLGUARD_ATTACK_LAB_TARGETS).`)
        : null,
      h("details", {}, h("summary", { class: "small" }, "Kỳ vọng"),
        h("p", { class: "small" }, "Naive: ", scenario.expect_naive),
        h("p", { class: "small" }, "SQLGuard: ", scenario.expect_sqlguard)),
      h("div", { class: "row" }, actions),
    );
  }

  async function install(scenario) {
    try {
      const note = await api.labNote(scenario.target);
      const saved = await api.labSave(scenario.target, scenario.payload, note.revision);
      question.value = scenario.question;
      show(`Đã cài payload ${scenario.id} vào ${scenario.target} (revision ${saved.revision}).`, "ok");
    } catch (error) {
      show(error.message, "error");
    }
  }

  async function restore(target) {
    try {
      const note = await api.labNote(target);
      if (note.revision === note.baseline_revision) {
        show(`${target} đang ở baseline, không cần restore.`, "ok");
        return;
      }
      const restored = await api.labRestore(target, note.revision);
      show(`Đã restore ${target} về baseline (revision ${restored.revision}).`, "ok");
    } catch (error) {
      show(error.message, "error");
    }
  }

  async function run() {
    const text = question.value.trim();
    if (!text || busy) return;
    busy = true;
    runButton.disabled = true;
    const started = performance.now();
    status.replaceChildren(spinner(), " Đang chạy SQLGuard rồi naive agent…");
    results.replaceChildren();
    try {
      const data = await api.compare(text, role.value);
      const seconds = ((performance.now() - started) / 1000).toFixed(1);
      status.textContent = `Xong sau ${seconds} giây.`;
      results.replaceChildren(
        labRevisionsLine(data.lab_revisions) || h("span"),
        h("div", { class: "compare-grid" },
          naiveColumn(data.naive, data.symptoms.naive, data.naive_model_label),
          sqlguardColumn(data.sqlguard, data.symptoms.sqlguard)));
      results.scrollIntoView({ behavior: "smooth", block: "start" });
    } catch (error) {
      status.textContent = "";
      results.replaceChildren(h("div", { class: "error-box", role: "alert" }, error.message));
    } finally {
      busy = false;
      runButton.disabled = false;
    }
  }
}

function symptomList(symptoms) {
  return h("ul", { class: "symptoms" }, symptoms.map((item) => {
    const state = item.triggered === null ? "na" : item.triggered ? "hit" : "clear";
    const mark = state === "hit" ? "⚠" : state === "clear" ? "✓" : "–";
    return h("li", { class: `symptom ${state}` },
      h("span", { class: "symptom-mark", "aria-hidden": "true" }, mark),
      h("span", {}, item.label,
        state === "na" ? h("span", { class: "muted" }, " (không áp dụng)") : null,
        item.detail && state === "hit" ? h("span", { class: "symptom-detail" }, `: ${item.detail}`) : null));
  }));
}

function rowsTable(columns, rows) {
  if (!columns || !columns.length) return h("p", { class: "muted small" }, "Không có cột nào.");
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, columns.map((name) => h("th", {}, name)))),
    h("tbody", {}, rows.length
      ? rows.map((row) => h("tr", {}, row.map((cell) => h("td", {}, cell === null ? "NULL" : String(cell)))))
      : h("tr", {}, h("td", { colspan: String(columns.length), class: "muted" }, "Không có dòng nào.")))));
}

function naiveColumn(naive, symptoms, modelLabel) {
  const hits = symptoms.filter((item) => item.triggered).length;
  return h("section", { class: "compare-column naive" },
    h("div", { class: "compare-head" },
      h("h2", {}, "Naive agent"),
      h("span", { class: hits ? "badge refused" : "badge full" }, `${hits} biểu hiện`)),
    h("p", { class: "muted small" }, modelLabel, ` · ${naive.model_calls} lần gọi model · status ${naive.status}`
      + (naive.error_category ? ` (${naive.error_category})` : "")),
    symptomList(symptoms),
    h("h3", {}, "Câu trả lời do model viết"),
    h("div", { class: "answer-box" }, renderNaiveMarkdown(naive.answer_markdown)),
    h("h3", {}, `Lời gọi execute_sql (${naive.tool_calls})`),
    naive.steps.map((step, index) => h("div", { class: "tool-step" },
      h("p", { class: "small" }, h("strong", {}, `#${index + 1}`), index ? " (model tự gọi thêm)" : ""),
      h("pre", { class: "sql-box wrap" }, step.sql),
      step.error
        ? h("div", { class: "error-box" }, step.error)
        : rowsTable(step.columns, step.rows))),
  );
}

function sqlguardColumn(result, symptoms) {
  const hits = symptoms.filter((item) => item.triggered).length;
  const page = result.result;
  return h("section", { class: "compare-column guarded" },
    h("div", { class: "compare-head" },
      h("h2", {}, "SQLGuard"),
      h("span", { class: hits ? "badge refused" : "badge full" }, `${hits} biểu hiện`)),
    h("p", { class: "muted small" }, `${result.planner || "planner"} ${result.model || ""} · role ${result.role}`),
    symptomList(symptoms),
    h("h3", {}, "Kết quả"),
    h("p", {}, h("span", { class: `badge ${result.status}` }, result.status), " ", result.reason),
    result.possible_injection ? injectionNotice() : null,
    h("p", { class: "muted small" }, "Không có LLM viết câu trả lời: dữ liệu chỉ hiện dưới dạng bảng."),
    result.sql ? h("pre", { class: "sql-box wrap" }, result.sql) : null,
    h("p", { class: "small" }, `Gate: ${result.gate.status}`, result.gate.reason ? ` (${result.gate.reason})` : ""),
    page ? rowsTable(page.columns, page.rows) : null,
  );
}
