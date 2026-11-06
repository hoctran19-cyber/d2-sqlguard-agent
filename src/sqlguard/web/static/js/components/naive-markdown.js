// Render tối thiểu cho câu trả lời của naive agent (chỉ dùng ở trang so sánh).
// Hỗ trợ: đoạn văn, xuống dòng, **đậm**, bảng kiểu "| a | b |" và ảnh ![alt](url).
// Mọi chữ đi qua textContent / createElement (không innerHTML) nên <script> trong câu trả lời
// chỉ hiện thành chữ. Ảnh http(s) ngoài thì CÓ được tải: đó là điểm yếu cố ý của kịch bản N-I3
// (kênh exfiltration), xem docs/threat-model/NAIVE_AGENT_DEMO.md.

import { h } from "../dom.js";

const INLINE = /\*\*([^*\n]+)\*\*|!\[([^\]\n]*)\]\(([^)\s]+)\)/g;

/** Các nút inline của một dòng: chữ thường, <strong>, <img>. */
function inline(text) {
  const nodes = [];
  let last = 0;
  for (const match of text.matchAll(INLINE)) {
    if (match.index > last) nodes.push(text.slice(last, match.index));
    if (match[1] !== undefined) {
      nodes.push(h("strong", {}, match[1]));
    } else {
      nodes.push(image(match[2], match[3]) ?? match[0]);
    }
    last = match.index + match[0].length;
  }
  if (last < text.length) nodes.push(text.slice(last));
  return nodes;
}

/** <img> cho URL http(s); scheme khác (javascript:, data:) giữ nguyên dạng chữ. */
function image(alt, url) {
  let parsed;
  try { parsed = new URL(url); } catch { return null; }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
  const img = document.createElement("img");
  img.alt = alt;
  img.src = parsed.href;
  img.className = "naive-image";
  img.referrerPolicy = "no-referrer";
  return img;
}

function cells(line) {
  return line.trim().replace(/^\|/, "").replace(/\|$/, "").split("|").map((cell) => cell.trim());
}

function table(lines) {
  const rows = lines.filter((line) => !/^\|?\s*:?-{3,}/.test(line.trim()));
  const [head, ...body] = rows.map(cells);
  return h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, (head || []).map((cell) => h("th", {}, inline(cell))))),
    h("tbody", {}, body.map((row) => h("tr", {}, row.map((cell) => h("td", {}, inline(cell))))))));
}

function paragraph(lines) {
  const children = [];
  lines.forEach((line, index) => {
    if (index) children.push(h("br"));
    children.push(...inline(line));
  });
  return h("p", {}, children);
}

/** Markdown (chuỗi) -> phần tử DOM. Chuỗi rỗng cho ra thông báo "không có câu trả lời". */
export function renderNaiveMarkdown(markdown) {
  const text = String(markdown || "").replace(/\r\n?/g, "\n").trim();
  if (!text) return h("p", { class: "muted" }, "(Model không trả câu trả lời)");
  const blocks = text.split(/\n\s*\n/);
  return h("div", { class: "naive-answer" }, blocks.map((block) => {
    const lines = block.split("\n");
    return lines.every((line) => line.trim().startsWith("|")) ? table(lines) : paragraph(lines);
  }));
}
