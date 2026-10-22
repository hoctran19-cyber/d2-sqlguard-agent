// Tiện ích tạo phần tử DOM an toàn.
// Mọi nội dung chữ đều đi qua textContent (không dùng innerHTML) nên dữ liệu từ database
// hay từ câu hỏi người dùng không thể chèn HTML/script vào trang.

/**
 * Tạo một phần tử HTML.
 * @param {string} tag   tên thẻ, ví dụ "div"
 * @param {object} attrs thuộc tính; "class" là className, "on..." là sự kiện (onclick, ...)
 * @param  {...any} children phần tử con hoặc chuỗi chữ
 */
export function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else if (value === true) node.setAttribute(key, "");
    else node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === undefined || child === null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

/** Vòng xoay chờ (spinner) nhỏ. */
export function spinner() {
  return h("span", { class: "spinner", "aria-hidden": "true" });
}
