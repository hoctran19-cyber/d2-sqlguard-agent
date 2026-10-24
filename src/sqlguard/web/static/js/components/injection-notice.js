// Cảnh báo dùng chung khi sanitizer gắn cờ possible_injection trên kết quả.
// Nội dung nghi vấn vẫn hiện trong bảng (dưới dạng chữ), nhưng người dùng được báo rõ.

import { h } from "../dom.js";

export function injectionNotice() {
  return h("div", { class: "notice-box injection-notice", role: "alert" },
    h("strong", {}, "Kết quả có nội dung đáng ngờ"),
    h("p", {}, "Một số ô trông như chỉ dẫn (ví dụ trong ghi chú). Chúng chỉ được hiển thị "
      + "như dữ liệu và không được dùng làm chỉ dẫn cho agent."));
}

/** Dòng "run này đọc note revision N" từ lab_revisions; null khi Attack Lab tắt hoặc chưa ghi gì. */
export function labRevisionsLine(labRevisions) {
  const entries = Object.entries(labRevisions || {});
  if (!entries.length) return null;
  const text = entries
    .map(([target, info]) => `${target}: revision ${info.revision}`
      + (info.content_hash ? ` (hash ${String(info.content_hash).slice(0, 8)})` : ""))
    .join(" · ");
  return h("p", { class: "muted small lab-revisions" }, `Attack Lab — note lúc run bắt đầu: ${text}`);
}
