// Trang Attack Lab (chỉ admin, chỉ hiện khi server bật lab): tiêm payload vào note của bản sao lab,
// khôi phục về baseline và xem lịch sử revision. Mọi nội dung note hiện bằng textContent.

import { api } from "../api.js";
import { h, spinner } from "../dom.js";

const MAX_LENGTH = 2000;

export async function renderLabPage(container) {
  container.replaceChildren(h("div", { class: "page" }, spinner(), " Đang tải Attack Lab…"));
  let targets;
  try {
    targets = (await api.labTargets()).targets;
  } catch (error) {
    container.replaceChildren(h("div", { class: "page" },
      h("h1", { class: "page-title" }, "Attack Lab"),
      h("div", { class: "error-box", role: "alert" }, error.message)));
    return;
  }

  const state = { target: targets[0] || null, revision: 0, busy: false };
  const select = h("select", { class: "lab-target", "aria-label": "Target" },
    targets.map((target) => h("option", { value: target }, target)));
  const current = h("pre", { class: "sql-box lab-current" });
  const meta = h("p", { class: "muted small" });
  const input = h("textarea", {
    class: "sql-input", rows: "5", maxlength: String(MAX_LENGTH), spellcheck: "false",
    "aria-label": "Nội dung note mới",
  });
  const counter = h("span", { class: "muted small" }, `0 / ${MAX_LENGTH}`);
  const message = h("div", { class: "hidden", role: "status" });
  const history = h("div", { class: "table-wrap lab-history" });
  const saveButton = h("button", { class: "btn", onclick: save }, "Lưu payload");
  const restoreButton = h("button", { class: "btn secondary", onclick: restore }, "Restore về baseline");
  const reloadButton = h("button", { class: "btn secondary", onclick: () => load() }, "Tải lại");

  input.addEventListener("input", () => {
    counter.textContent = `${input.value.length} / ${MAX_LENGTH}`;
  });
  select.addEventListener("change", () => { state.target = select.value; load(); });

  container.replaceChildren(h("div", { class: "page lab-page" },
    h("h1", { class: "page-title" }, "Attack Lab"),
    h("div", { class: "notice-box" },
      h("strong", {}, "Chỉ dùng cho demo"),
      h("p", {}, "Ghi vào bản sao lab của database, không phải file gốc. Không ghi được khi đang có "
        + "câu hỏi chạy; hỏi bằng tài khoản operator ở cửa sổ khác.")),
    targets.length ? null : h("p", { class: "muted" }, "Chưa cấu hình target nào cho lab."),
    h("label", { class: "field-label" }, "Target"), select,
    h("label", { class: "field-label" }, "Note hiện tại"), current, meta,
    h("label", { class: "field-label" }, "Payload mới"), input,
    h("div", { class: "row" }, saveButton, restoreButton, reloadButton, counter),
    message,
    h("label", { class: "field-label" }, "Lịch sử revision (không chứa nội dung)"), history,
  ));
  if (state.target) load();

  function setBusy(busy) {
    state.busy = busy;
    for (const button of [saveButton, restoreButton, reloadButton]) button.disabled = busy;
    restoreButton.disabled = busy || state.revision === 0;
  }

  function show(text, kind) {
    message.className = kind === "error" ? "error-box" : "ok-box";
    message.textContent = text;
  }

  async function load() {
    if (!state.target) return;
    setBusy(true);
    try {
      const note = await api.labNote(state.target);
      state.revision = note.revision;
      current.textContent = note.content ?? "(NULL)";
      meta.textContent = `Revision ${note.revision} (baseline = ${note.baseline_revision})`;
      renderHistory((await api.labHistory(state.target)).history);
      message.className = "hidden";
    } catch (error) {
      show(error.message, "error");
    } finally {
      setBusy(false);
    }
  }

  async function mutate(action, okText) {
    if (state.busy) return;
    setBusy(true);
    try {
      await action();
      await load();
      show(okText, "ok");
    } catch (error) {
      show(error.message, "error");
      setBusy(false);
      restoreButton.disabled = state.revision === 0;
    }
  }

  function save() {
    return mutate(async () => {
      await api.labSave(state.target, input.value, state.revision);
    }, "Đã lưu payload.");
  }

  function restore() {
    return mutate(async () => {
      await api.labRestore(state.target, state.revision);
    }, "Đã restore về baseline.");
  }

  function renderHistory(items) {
    history.replaceChildren(h("table", {},
      h("thead", {}, h("tr", {}, ["Rev", "Hành động", "Hash", "Độ dài", "User", "Thời điểm"]
        .map((name) => h("th", {}, name)))),
      h("tbody", {}, items.map((item) => h("tr", {},
        h("td", {}, item.revision), h("td", {}, item.action),
        h("td", {}, item.content_hash ? item.content_hash.slice(0, 8) : "—"),
        h("td", {}, item.length), h("td", {}, item.user_id), h("td", {}, item.timestamp))))));
  }
}
