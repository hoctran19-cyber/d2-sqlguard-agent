// Các hàm gọi API backend. Cookie session được trình duyệt tự gửi kèm (HttpOnly).

/** Lỗi API có kèm mã HTTP để nơi gọi xử lý (ví dụ 401 thì quay về trang login). */
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

async function request(method, path, body) {
  const options = { method, headers: {} };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  let data = null;
  try { data = await response.json(); } catch { /* phản hồi không phải JSON */ }
  if (!response.ok) {
    const detail = data && data.detail ? data.detail : `HTTP ${response.status}`;
    // Phiên đăng nhập hết hạn: quay về trang login.
    if (response.status === 401 && path !== "/api/login") window.location.href = "/login";
    throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  return data;
}

export const api = {
  login: (username, password) => request("POST", "/api/login", { username, password }),
  logout: () => request("POST", "/api/logout", {}),
  me: () => request("GET", "/api/me"),
  info: () => request("GET", "/api/info"),
  tables: () => request("GET", "/api/tables"),
  // Chạy SQL thủ công, lấy một trang 20 dòng.
  runSql: (sql, page = 1) => request("POST", "/api/sql", { sql, page }),
  // Câu hỏi mẫu của planner demo.
  samples: () => request("GET", "/api/query/samples"),
  // Gửi câu hỏi ngôn ngữ tự nhiên cho agent.
  ask: (question) => request("POST", "/api/query", { question }),
};
