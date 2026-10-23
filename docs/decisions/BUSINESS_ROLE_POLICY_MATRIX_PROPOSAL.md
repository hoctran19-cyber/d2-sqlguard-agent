# Đề xuất ma trận policy business role theo `financial.sqlite`

**Đề xuất — chưa được phê duyệt; chưa được thực thi.** Tài liệu này không cấp quyền SQL.
Các quyền dưới đây là đề xuất least privilege để nhóm xem xét, không phải chính sách đã được
chấp thuận. API dữ liệu của business role phải tiếp tục bị từ chối cho tới khi nhóm phê duyệt
ma trận, điều kiện nghiệp vụ và cách enforce.

## 1. Quyết định schema và phạm vi

Theo quyết định người dùng trong Task 3, `data/financial.sqlite` với tám bảng được chọn làm
schema chuẩn của proposal này, thay cho giả định dùng BIRD Mini-Dev Financial upstream nguyên
bản. Đây là lựa chọn schema cho thiết kế; **không** xác nhận nguồn tải, phiên bản, license,
provenance, tính xác thực hoặc quyền phân phối của file/các cột bổ sung.

`admin` và `evaluator` là system role riêng, không thuộc ma trận ba business role:
`operator`, `analyst`, `credit_officer`. Không ánh xạ bất kỳ role nào sang `teller`, `credit`,
hoặc `risk`; các grant trong `bird_financial_v1.json` không được tái sử dụng cho business role.

### 1.1. Schema quan sát trực tiếp trong workspace

Trong phiên này đã mở `/Users/johnnytran/Projects/d2-sqlguard-agent/data/financial.sqlite`
bằng SQLite URI `mode=ro`. Chỉ đọc metadata/schema và đếm số bản ghi; không đọc nội dung từng
bản ghi, không sửa database. Đây là kết quả của file hiện có trong workspace hiện tại, không
chứng minh provenance hoặc schema của bản sao khác.

- Kích thước: **71.294.976 byte** (68 MiB).
- SHA-256 đo được của file hiện tại:
  `ec45f11d8568fa4dcc2ce60594a37fd9db643d6b0fc01b4a61090faeea21eba0`. Hash này chỉ nhận
  diện chính xác file đã kiểm tra; không phải checksum upstream đã được xác thực.
- SQLite runtime dùng để kiểm tra: **3.50.2**.
- `PRAGMA integrity_check`: `ok`.
- `PRAGMA foreign_key_check`: không trả về vi phạm.
- Tổng bản ghi tính từ tám bảng: **1.079.680**. Con số được nêu trong thông tin đầu vào Task 3
  là 1.124.676, chênh **44.996**; cần đối chiếu trước khi coi số liệu tham khảo là chính xác.
- Các số đếm từng bảng bên dưới là ảnh chụp của file đã kiểm tra, không phải invariant policy.

| Bảng | Bản ghi quan sát | Cột theo schema thực tế đã đọc |
| --- | ---: | --- |
| `district` | 77 | `district_id INTEGER NOT NULL PK`; `A2 TEXT NOT NULL`; `A3 TEXT NOT NULL`; `A4 TEXT NOT NULL`; `A5 TEXT NOT NULL`; `A6 TEXT NOT NULL`; `A7 TEXT NOT NULL`; `A8 INTEGER NOT NULL`; `A9 INTEGER NOT NULL`; `A10 REAL NOT NULL`; `A11 INTEGER NOT NULL`; `A12 REAL NULL`; `A13 REAL NOT NULL`; `A14 INTEGER NOT NULL`; `A15 INTEGER NULL`; `A16 INTEGER NOT NULL` |
| `client` | 5.369 | `client_id INTEGER NOT NULL PK`; `gender TEXT NOT NULL`; `birth_date DATE NOT NULL`; `district_id INTEGER NOT NULL`; `id_number TEXT NULL`; `full_name TEXT NULL`; `address TEXT NULL` |
| `account` | 4.500 | `account_id INTEGER NOT NULL PK`; `district_id INTEGER NOT NULL`; `frequency TEXT NOT NULL`; `date DATE NOT NULL`; `service_note TEXT NULL` |
| `disp` | 5.369 | `disp_id INTEGER NOT NULL PK`; `client_id INTEGER NOT NULL`; `account_id INTEGER NOT NULL`; `type TEXT NOT NULL` |
| `card` | 892 | `card_id INTEGER NOT NULL PK`; `disp_id INTEGER NOT NULL`; `type TEXT NOT NULL`; `issued DATE NOT NULL`; `placeholder TEXT NULL` |
| `loan` | 682 | `loan_id INTEGER NOT NULL PK`; `account_id INTEGER NOT NULL`; `date DATE NOT NULL`; `amount INTEGER NOT NULL`; `duration INTEGER NOT NULL`; `payments REAL NOT NULL`; `status TEXT NOT NULL` |
| `order` | 6.471 | `order_id INTEGER NOT NULL PK`; `account_id INTEGER NOT NULL`; `bank_to TEXT NOT NULL`; `account_to INTEGER NOT NULL`; `amount REAL NOT NULL`; `k_symbol TEXT NOT NULL`; `note TEXT NULL` |
| `trans` | 1.056.320 | `trans_id INTEGER NOT NULL PK`; `account_id INTEGER NOT NULL`; `date DATE NOT NULL`; `type TEXT NOT NULL`; `operation TEXT NULL`; `amount INTEGER NOT NULL`; `balance INTEGER NOT NULL`; `k_symbol TEXT NULL`; `bank TEXT NULL`; `account INTEGER NULL` |

Schema thực tế có **61 cột**. Trong bảy cột được yêu cầu xem xét đặc biệt, sáu cột sau có
trong file: `client.full_name`, `client.address`, `client.id_number`, `account.service_note`,
`card.placeholder`, `order.note`. **`trans.note` không có trong bảng `trans` thực tế** đã
kiểm tra. Vì vậy, chưa được đưa `trans.note` vào allowlist/denylist thực thi cho schema này;
nếu schema đổi hoặc cột được bổ sung thì phải kiểm tra lại và fail closed khi drift. Sáu cột
tồn tại được giữ nguyên trong mô tả schema, không đổi tên hay xóa khỏi proposal.

Kiểu dữ liệu SQLite là khai báo affinity/kiểu của cột, không chứng minh ngữ nghĩa hay loại
giá trị chứa trong đó. Đặc biệt `district.A4`–`A7` được khai báo `TEXT`; cần xác minh dictionary
và giá trị trước khi coi chúng là số liệu. `district.A9` hiện chưa có diễn giải đủ tin cậy
trong dictionary local.

### 1.2. Quan hệ khóa ngoại được khai báo

`PRAGMA foreign_key_list` xác nhận đúng các quan hệ dưới đây. Đây là quan hệ do SQLite khai
báo, không phải suy luận chỉ từ tên cột:

- `disp.client_id` → `client.client_id`
- `disp.account_id` → `account.account_id`
- `card.disp_id` → `disp.disp_id`
- `account.district_id` → `district.district_id`
- `client.district_id` → `district.district_id`
- `trans.account_id` → `account.account_id`
- `loan.account_id` → `account.account_id`
- `order.account_id` → `account.account_id`

`foreign_key_check` không phát hiện vi phạm trên file đã kiểm tra. Điều này chỉ xác nhận các
khóa ngoại được khai báo; không xác nhận các liên hệ nghiệp vụ ngoài danh sách trên.

## 2. Nguồn gốc database và giới hạn bằng chứng

Kiểm tra file cục bộ xác nhận schema/các metadata ở §1 tại thời điểm kiểm tra. Các thông tin
sau vẫn **CHƯA XÁC MINH**:

1. Nguồn tải hoặc tổ chức/cá nhân cung cấp database gốc.
2. Tên dataset upstream, phiên bản/revision và ngày tải.
3. License áp dụng cho file cụ thể và điều kiện sử dụng/phân phối.
4. File là bản gốc, bản chuyển đổi, hay bản được bổ sung dữ liệu/cột nội bộ.
5. Nguồn và lý do của sáu cột cần xác minh (`client.id_number`,
   `client.full_name`, `client.address`, `account.service_note`, `card.placeholder`,
   `order.note`).
6. Các cột bổ sung chứa dữ liệu cá nhân, tổng hợp, giả lập hay văn bản tự do không đáng tin.
   Chưa đọc giá trị của chúng để tránh suy đoán nội dung từ tên cột.
7. Tên/định danh người đã cung cấp file và chuỗi quản lý file trước khi file vào workspace.
8. Bằng chứng cho các số liệu báo cáo ở phiên trước và chênh lệch tổng bản ghi 44.996 với số
   lượng trong Task 3.
9. Ý nghĩa nghiệp vụ đáng tin của `district.A4`–`A7`, `district.A9` và các cột district khác.

Trước khi dùng database làm đầu vào cho policy production, nhóm cần hoàn tất checklist:

- Ghi nguồn tải/cung cấp, tên dataset, version/revision, ngày nhận/tải và người chịu trách
  nhiệm provenance.
- Ghim SHA-256 của đúng artifact nguồn và phân biệt rõ với hash file local ở §1.1.
- Xác nhận bằng tài liệu license/điều kiện phân phối có thẩm quyền.
- Ghi lại bước chuyển đổi/nạp dữ liệu và xác định nguồn gốc từng cột đang cần xác minh; không
  giả định chúng chắc chắn được tạo nội bộ hoặc thuộc schema upstream.
- Phân loại nội dung/độ nhạy của sáu cột bổ sung mà không mặc định chúng là thật hay giả.
- Lưu schema `sqlite_master`, kiểu/nullability/PK/FK và phiên bản SQLite cho artifact đã duyệt.
- Chạy lại `PRAGMA integrity_check` và `PRAGMA foreign_key_check` trên đúng artifact được duyệt
  khi triển khai; kết quả hiện tại chỉ áp dụng cho file trong workspace phiên này.
- Nhóm dữ liệu, chủ sở hữu nghiệp vụ và người phê duyệt policy ký xác nhận các điểm còn mở.

Không đưa file database nhị phân vào Git. Báo cáo số lượng bản ghi chỉ là metadata kiểm tra,
không được hard-code thành policy hoặc invariant runtime/test.

## 3. Nguyên tắc đề xuất và cách đọc ma trận

- Ma trận dưới đây là **đề xuất least privilege để review**, không phải grant đã phê duyệt.
- `Được dùng nội bộ` không đồng nghĩa `được trả ra`: cột khóa có thể cần cho JOIN hoặc
  `COUNT(DISTINCT ...)` nhưng không được xuất trong kết quả.
- Cột không nằm trong phần cho phép của role được **từ chối mặc định**.
- Quyền cột, phạm vi dòng (`row-level scope`) và dạng truy vấn (`query-shape`) là ba lớp khác
  nhau; không suy ra quyền ở lớp này từ lớp kia.
- Cho tới khi có phê duyệt và runtime tương ứng, quyền hiệu lực của cả ba business role vẫn là
  **không truy vấn dữ liệu**.
- `trans.note` không tồn tại trong schema được kiểm tra. Các tham chiếu lịch sử tới cột này là
  drift cần xử lý, không phải quyền trên database hiện tại.

## 4. Ma trận đề xuất

### 4.1. `operator`

**Mục đích tối thiểu giả định để review:** hỗ trợ vận hành tài khoản/quan hệ khách hàng. Đây
là suy luận use-case từ nhãn role, chưa có căn cứ nghiệp vụ được nhóm phê duyệt. Không mặc định
operator cần xem toàn bộ lịch sử giao dịch hoặc thông tin định danh trực tiếp.

| Bảng | Cột đề xuất dùng | Cột bị từ chối mặc định | Căn cứ / điều kiện |
| --- | --- | --- | --- |
| `client` | `client_id` chỉ dùng nội bộ để nối quan hệ | `gender`, `birth_date`, `district_id`, `id_number`, `full_name`, `address` | ID vẫn là khóa liên kết có rủi ro tái nhận dạng; không xuất trực tiếp. Các thuộc tính cá nhân cần phê duyệt use-case. |
| `disp` | `disp_id`, `client_id`, `account_id`, `type` chỉ dùng cho tra cứu quan hệ được phân công | Không có cột nào được xuất nếu chưa có row scope | Cần nối khách hàng với tài khoản, nhưng không có dữ liệu phân công trong schema hiện tại. |
| `account` | `account_id` nội bộ; `district_id`, `frequency`, `date` chỉ khi cần hiển thị metadata tài khoản được giao | `service_note` | Metadata không đồng nghĩa quyền truy cập mọi tài khoản; note chưa xác minh và là nội dung tự do. |
| `trans` | Không cấp quyền mặc định | Tất cả: `trans_id`, `account_id`, `date`, `type`, `operation`, `amount`, `balance`, `k_symbol`, `bank`, `account` | Không mặc định cho xem chi tiết/hàng triệu dòng lịch sử. Nếu có use-case hỗ trợ giao dịch cụ thể, cần duyệt trường tối thiểu và ràng buộc dòng. |
| `card` | Không cấp quyền mặc định | `card_id`, `disp_id`, `type`, `issued`, `placeholder` | Không có use-case cần thẻ được xác nhận; placeholder chưa xác minh. |
| `loan` | Không cấp quyền mặc định | `loan_id`, `account_id`, `date`, `amount`, `duration`, `payments`, `status` | Không suy từ role vận hành sang quyền đọc tín dụng. |
| `order` | Không cấp quyền mặc định | `order_id`, `account_id`, `bank_to`, `account_to`, `amount`, `k_symbol`, `note` | Thông tin người nhận/tài khoản đối tác và note nhạy cảm; cần use-case riêng. |
| `district` | Không cấp quyền mặc định | `district_id`, `A2`–`A16` | Chưa có tác vụ vận hành nào yêu cầu dữ liệu khu vực. |

**JOIN:** chỉ xem xét đường nối `client`–`disp`–`account` theo khóa ngoại đã khai báo, và chỉ
trong tập bản ghi được phân công. Mọi JOIN tới `trans`, `card`, `loan`, `order` hoặc `district`
bị từ chối mặc định cho tới khi được phê duyệt. Không cho `NATURAL JOIN`/`JOIN ... USING`.

**Dạng truy vấn:** đề xuất cho phép SELECT metadata hạn chế sau khi có row scope; không cho
phép raw transaction history, ghi dữ liệu, DDL, truy vấn catalog, PRAGMA, ATTACH, CTE,
subquery, UNION hoặc cú pháp chưa hỗ trợ. Chưa có căn cứ cho aggregate riêng theo operator.
Row count/pagination cũng phải áp dụng row scope và không được tiết lộ tổng cỡ dữ liệu ngoài
phạm vi.

**Rủi ro và phê duyệt:** `client_id`, `account_id`, tên/địa chỉ và chuỗi quan hệ có thể nhận
dạng lại khách hàng. Cần xác nhận operator có cần xem dữ liệu chi tiết không, có được thấy
thông tin liên hệ không, và tài khoản/khách hàng nào được giao. Thiếu assignment data thì
không thể enforce “chỉ khách hàng của tôi”.

### 4.2. `analyst` — chỉ trả kết quả tổng hợp

**Đề xuất:** analyst không nhận bản ghi từng khách hàng, tài khoản, thẻ, khoản vay hoặc giao
dịch. Chỉ được nhận kết quả tổng hợp đã qua kiểm tra/suppression. Đây là đề xuất để duyệt dựa
trên yêu cầu Task 3, chưa phải policy được phê duyệt. Không được coi việc ẩn cột trong UI,
system prompt, tên hàm SQL hoặc cấm `SELECT *` là đủ để bảo đảm aggregate-only.

| Bảng | Chỉ dùng nội bộ trong truy vấn tổng hợp | Chiều/số liệu ứng viên | Từ chối mặc định |
| --- | --- | --- | --- |
| `client` | `client_id` chỉ cho `COUNT(DISTINCT ...)`; `district_id` chỉ nối/nhóm qua dimension đã duyệt | Không xuất khóa khách hàng; chưa đề xuất chiều nhân khẩu học | `gender`, `birth_date`, `id_number`, `full_name`, `address`; không trả `client_id`/`district_id` nguyên bản |
| `disp` | `client_id`, `account_id` chỉ nối hoặc đếm distinct trong phép tổng hợp được duyệt | Chưa đề xuất `type` cho tới khi xác nhận ngữ nghĩa và nguy cơ nhóm nhỏ | `disp_id`, `type` và mọi output row-level; không xuất khóa |
| `account` | `account_id` chỉ nối/đếm distinct; `district_id` chỉ nối dimension | `frequency` là chiều ứng viên; `date` chỉ được bucket tháng/năm sau khi chuẩn hóa | `service_note` (và drift schema); không xuất account ID, ngày chi tiết hoặc dòng tài khoản |
| `trans` | `account_id` chỉ nối/đếm distinct | `date` theo bucket tháng; `type`, `operation`, `k_symbol` là chiều ứng viên; `amount` chỉ làm measure trong `SUM`/`AVG`/`COUNT` được duyệt | `trans_id`, `balance`, `bank`, `account`; mọi dòng giao dịch; `trans.note` không có trong schema quan sát và phải từ chối nếu xuất hiện do drift |
| `district` | `district_id` chỉ dùng nối/nhóm nội bộ | `A2`/`A3` là chiều ứng viên nhưng phải suppression nhóm nhỏ. `A8`, `A10`–`A16` chỉ xem xét làm measure sau khi xác nhận định nghĩa; `A4`–`A7` đang có kiểu khai báo TEXT nên không dùng làm số liệu nếu chưa kiểm tra | `A9` do chưa có mô tả đáng tin; không xuất khóa district thô; không dùng cột chưa xác minh |
| `card` | Không cấp quyền | Không có | Tất cả: `card_id`, `disp_id`, `type`, `issued`, `placeholder` |
| `loan` | Không cấp quyền | Không có | Tất cả: `loan_id`, `account_id`, `date`, `amount`, `duration`, `payments`, `status` |
| `order` | Không cấp quyền | Không có | Tất cả: `order_id`, `account_id`, `bank_to`, `account_to`, `amount`, `k_symbol`, `note` |

**Hàm tổng hợp đề xuất:**

- `COUNT`: có thể cho phép để đếm nhóm; `COUNT(*)` và `COUNT(DISTINCT key)` phải bị ràng buộc
  bởi AST, tập bảng/khóa được duyệt, nhóm đầu ra và suppression. Không công khai tổng số dòng
  chưa suppression.
- `SUM`, `AVG`: chỉ trên measure đã duyệt (ứng viên `trans.amount`); không cho xuất dữ liệu
  measure theo từng record. Cần giới hạn ngữ cảnh lọc/nhóm để tránh tổng của một người hoặc một
  tài khoản.
- `MIN`, `MAX`: **từ chối mặc định** vì cực trị có thể tương ứng một cá nhân/giao dịch duy nhất.
  Chỉ xem xét khi có use-case, cohort đủ điều kiện và cơ chế output/suppression được duyệt.
- Không hàm nào được tự động cấp chỉ vì `bird_financial_v1.json` có tên hàm trong danh sách
  functions.

**Quy tắc output và query-shape cần duyệt:** chỉ cho phép biểu thức kết quả là aggregate được
phê duyệt hoặc dimension đã duyệt; không trả cột ID/giá trị cá thể. Cấm grouping theo
`client_id`, `account_id`, `disp_id`, `loan_id`, `card_id`, `order_id`, `trans_id` hoặc ngày
chính xác; cấm predicate tiết lộ một thực thể cụ thể. `HAVING` chỉ trên aggregate đã duyệt;
`ORDER BY` chỉ trên dimension/aggregate được trả ra. Không hỗ trợ subquery, CTE, UNION và
window function cho tới khi validator đệ quy được triển khai. `COUNT(*)` không tự được coi là
vô hại: toàn cục hoặc ở nhóm nhỏ có thể làm lộ tồn tại/hoạt động.

**Nhóm nhỏ và truy vấn lặp:** ngưỡng cohort hiện là **TBD — cần phê duyệt**, không tự đặt số.
Query service cần suppress nhóm dưới ngưỡng, xử lý complementary suppression khi tổng cho phép
suy ra nhóm bị ẩn, và không trả tổng số nhóm/dòng bị suppress. Ngưỡng đơn lẻ không bảo đảm
chống suy diễn. Hai truy vấn gần nhau có thể bị lấy hiệu để lộ cá nhân; cần cân nhắc ngân sách
truy vấn, lưu fingerprint tham số/truy vấn, giới hạn lặp theo user/session và/hoặc cơ chế privacy
được nhóm duyệt. Không tuyên bố cơ chế nào đã tồn tại.

**Vị trí enforce đề xuất cho analyst:**

| Biện pháp | Vị trí cần enforce | Giới hạn hiện tại |
| --- | --- | --- |
| Phân biệt khóa nội bộ, chiều, measure, cột output; chỉ cho aggregate grammar đã duyệt | Khai báo trong policy và kiểm AST trước thực thi | `RolePolicy` hiện chỉ lưu allowlist cột; cần mở rộng policy/AST để nhận diện biểu thức, alias, ngữ cảnh sử dụng và output projection. |
| Kiểm tra từng đọc cột, cấm thao tác SQLite khác, giữ database chỉ đọc | `PolicySQLGate` và SQLite authorizer trong `SQLiteExecutor` | Authorizer xác nhận quyền đọc bảng/cột, không biết cột chỉ dùng nội bộ hay kết quả có aggregate-only. Không bỏ qua authorizer. |
| Thực hiện aggregate, suppression, complementary suppression; loại metadata/count rò rỉ và chỉ đóng gói kết quả đã kiểm tra | Query service/result wrapper | `SecureSqlTool` hiện có row/byte caps, sanitizer/canary/audit, nhưng chưa có cơ chế suppression hoặc kiểm tra aggregate result theo policy này. |
| Giảm rủi ro differencing từ truy vấn tương tự/lặp lại | Session/user-scoped query history, quota/budget và policy quyết định có trạng thái | Chưa có ngân sách privacy/query history được định nghĩa cho mục đích này; cần quyết định retention, thời hạn, giới hạn và xử lý concurrent requests. |

`COUNT(DISTINCT ...)`, subquery/CTE, JOIN, `HAVING`, `ORDER BY`, pagination và wrapper đếm
tổng dòng đều phải được validate như một phần của cùng AST/query plan. Hiện gate từ chối
subquery/CTE/set operation, đó là hành vi fail-closed cần giữ cho tới khi có validator đệ quy.
SQLite authorizer cũng không thể thay gate để xác nhận ngữ nghĩa aggregate. Không chạy
`COUNT(*)` wrapper riêng ngoài boundary được policy kiểm tra. Kể cả khi ngưỡng nhóm/suppression
được triển khai, nó không tự bảo đảm chống tái nhận dạng hoặc differencing.

### 4.3. `credit_officer`

**Mục đích tối thiểu giả định để review:** xử lý khoản vay được giao. Nhãn role không chứng
minh quyền đọc mọi khoản vay hoặc toàn bộ danh tính khách hàng. Chỉ xem xét dữ liệu khoản vay
liên kết với account/hồ sơ được phân công khi có nguồn assignment độc lập, đáng tin.

| Bảng | Cột đề xuất dùng | Cột bị từ chối mặc định | Căn cứ / điều kiện |
| --- | --- | --- | --- |
| `loan` | `loan_id`, `account_id` chỉ làm khóa nội bộ; `date`, `amount`, `duration`, `payments`, `status` chỉ cho hồ sơ được giao | Không xuất ID liên kết nếu không cần; các trường còn lại chưa có grant | Là dữ liệu cốt lõi cần review cho nghiệp vụ tín dụng, nhưng trường amount/repayment rất nhạy cảm và chỉ được đọc trong assignment scope. |
| `account` | `account_id` chỉ để nối | `district_id`, `frequency`, `date`, `service_note` | Chỉ dùng khóa để nối loan với quan hệ khách hàng. Metadata khác cần use-case riêng. |
| `disp` | `account_id`, `client_id`, `disp_id`, `type` chỉ để xác định quan hệ account–client; không xuất khóa theo mặc định | Không trả bản ghi `disp` | Cần xác định khách hàng liên quan tới khoản vay, nhưng quan hệ chủ/người được ủy quyền cần được phân biệt. |
| `client` | `client_id` chỉ làm khóa nối nội bộ nếu cần xác định hồ sơ | `gender`, `birth_date`, `district_id`, `id_number`, `full_name`, `address` | Không mặc định cấp PII hoặc định danh. Tên thật/định danh chỉ xem xét sau phê duyệt mục đích, phạm vi và cơ chế hiển thị tối thiểu. |
| `district` | Không cấp quyền mặc định | `district_id`, `A2`–`A16` | Không có căn cứ cho thấy district cần thiết để xử lý khoản vay. |
| `trans` | Không cấp quyền mặc định | `trans_id`, `account_id`, `date`, `type`, `operation`, `amount`, `balance`, `k_symbol`, `bank`, `account` | Không mặc định mở toàn bộ lịch sử giao dịch. Nếu thẩm định yêu cầu, cần duyệt rõ cột, khoảng thời gian và assignment scope. |
| `order` | Không cấp quyền mặc định | `order_id`, `account_id`, `bank_to`, `account_to`, `amount`, `k_symbol`, `note` | Tài khoản đối tác và note không được mặc định cần cho tín dụng. |
| `card` | Không cấp quyền mặc định | `card_id`, `disp_id`, `type`, `issued`, `placeholder` | Không có mục đích nghiệp vụ đã xác nhận. |

**JOIN:** chỉ xem xét `loan.account_id` → `account.account_id` → `disp.account_id` →
`disp.client_id` → `client.client_id`, theo khóa ngoại đã khai báo. Bắt buộc áp dụng
assignment scope cho loan/account trước khi dữ liệu được trả. `district`, `trans`, `order` và
`card` không tham gia JOIN theo mặc định. Không cho `NATURAL JOIN`/`JOIN ... USING`.

**Dạng truy vấn và rò rỉ:** SELECT theo hồ sơ được giao là ứng viên, không phải quyền hiện tại.
Không cho lọc để dò hồ sơ ngoài phạm vi, xuất danh sách định danh, pagination/count toàn bảng,
ghi dữ liệu hoặc SQL không hỗ trợ. Dữ liệu khoản vay chi tiết có thể nhạy cảm ngay cả khi
không kèm PII; cần audit truy cập, giới hạn hàng/thời gian và trả lỗi không tiết lộ nội dung DB.

## 5. Phân tách quyền và kiểm soát cần triển khai

| Lớp | Quyết định thiết kế |
| --- | --- |
| Quyền cột | Policy versioned chỉ rõ bảng/cột từng role; mọi cột không cấp bị từ chối ở projection, predicate, join, grouping, ordering và biểu thức. Không wildcard cấp mọi cột. |
| Row-level scope | Cần nguồn assignment server-side cho operator/credit officer; không lấy từ SQL/prompt/request. Không có dữ liệu assignment hiện trong schema này; cho tới khi có, không thể bật truy vấn chi tiết. |
| Query-shape | Gate phải parse AST và phân biệt cột dùng nội bộ với cột xuất ra; analyst chỉ được kết quả aggregate; các role khác chỉ được dạng truy vấn đã duyệt. Prompt LLM không phải kiểm soát bảo mật. |
| DB boundary | Dùng `SQLiteExecutor` với cùng policy và trusted role để enforce độc lập ở mỗi kết nối; giữ `mode=ro`, `query_only`, authorizer, giới hạn function và từ chối `NATURAL`/`USING`. Không bỏ qua executor. |
| Wrapper phân trang/đếm | Thực thi cả page và count trong cùng ranh giới đã validate, chỉ dựa trên SQL normalized. Đối với analyst, không trả `total_rows`/số nhóm trước suppression; count wrapper không được trở thành đường truy vấn phụ để bypass aggregate policy. |
| Analyst output | Query service kiểm tra shape kết quả, áp dụng ngưỡng/suppression đã duyệt, complementary suppression và giới hạn output; query history/budget cần thiết để quản lý truy vấn lặp/differencing. |
| Schema drift | Preflight đối chiếu đúng bảng/cột/kiểu/PK/FK với schema được duyệt. Phát hiện thêm/thiếu cột (đặc biệt `trans.note`) phải fail closed cho tới khi review. |
| Identity | Role chỉ lấy từ session server đã xác thực; không nhận từ body/header/query string hay LLM. Giữ `admin`/`evaluator` ngoài ma trận business. |

`RolePolicy` hiện mô hình hóa allowlist bảng/cột, khóa ngoại, hàm và giới hạn. `PolicySQLGate`
kiểm tra AST, giới hạn cấu trúc và các cột; hiện từ chối CTE, subquery và set operation.
`SQLiteExecutor` enforce authorizer ở DB nhưng không thể tự biết cột nào được xuất ra hay
result có aggregate-only. `SecureSqlTool` đóng vai trò ranh giới secure query trong runtime
hiện có. Không thành phần nào hiện cung cấp đầy đủ row assignment, aggregate-only, k-anonymity/
suppression hay chống differencing cho matrix này.

Web query path hiện tại vẫn dùng gate chỉ kiểm tra bảng và `FinancialDatabase` tự tạo query
đếm/trang; business role chưa được phép gọi API dữ liệu. Tài liệu này không thay đổi trạng
thái đó.

## 6. Câu hỏi chờ phê duyệt

1. Provenance, license, dataset version/revision và ngày nhận của `financial.sqlite` là gì?
   Ai xác nhận nguồn file và checksum nguồn upstream?
2. Sáu cột cần xác minh có trong file (`client.id_number`, `client.full_name`,
   `client.address`, `account.service_note`, `card.placeholder`, `order.note`) có nguồn gốc
   và mục đích gì? Chúng chứa dữ liệu cá nhân,
   synthetic, tổng hợp hay free-text không đáng tin? Vì sao thông tin trước đó nhắc
   `trans.note` trong khi bảng thực tế không có cột này?
3. Vì sao tổng row-count tham khảo 1.124.676 khác tổng đã đếm trực tiếp 1.079.680? Có file
   revision khác không?
4. `operator` có cần dữ liệu chi tiết hay chỉ metadata/trạng thái? Có cần PII hoặc lịch sử
   giao dịch? Làm sao định nghĩa và cung cấp danh sách account/client được giao?
5. `credit_officer` có cần xem tên/định danh khách hàng không, và giới hạn theo hồ sơ nào?
   Có cần transaction/order/card cho thẩm định không?
6. Analyst được phép những chiều nào? `gender` có bị cấm tuyệt đối không? Có được dùng
   district và thời gian tháng không?
7. Ngưỡng nhóm tối thiểu cho analyst là bao nhiêu? Ai phê duyệt quy tắc nhóm nhỏ,
   complementary suppression và tổng output?
8. Có cần ngân sách truy vấn/lịch sử truy vấn theo user để hạn chế differencing? Cửa sổ thời
   gian và số lần truy vấn do ai quyết định?
9. Có cho `MIN`/`MAX` không, hay chỉ `COUNT`/`SUM`/`AVG`? `COUNT(*)` và
   `COUNT(DISTINCT key)` có được phép trong ngữ cảnh nào?
10. Các trường note `account.service_note`, `order.note` có bị loại hoàn toàn không, hay được
    dùng nội bộ sau kiểm tra/sanitization? Lưu ý `trans.note` không tồn tại trong file hiện tại.
11. Ai là chủ sở hữu nghiệp vụ và người có thẩm quyền phê duyệt cuối cùng cho từng grant?
12. Xác nhận `admin` và `evaluator` tiếp tục là system role riêng ngoài business-role policy.

## 7. Kế hoạch cho task triển khai tiếp theo

1. Nhóm hoàn tất checklist provenance và chốt các câu hỏi ở §6; giữ API business role bị khóa.
2. Người phụ trách dữ liệu xác nhận file/revision cuối, nguồn/license, schema và ngữ nghĩa các
   cột bổ sung. Lưu manifest/hash như thông tin nhận diện artifact, không đưa database vào Git.
3. Người phụ trách nghiệp vụ duyệt allowlist cột, row-level scope, analyst aggregate grammar,
   ngưỡng/suppression, query budget và quy tắc output.
4. Tạo policy riêng có version cho đúng schema và đúng role `operator`, `analyst`,
   `credit_officer`; không đổi tên hoặc tái sử dụng grant `teller`/`credit`/`risk`.
5. Mở rộng gate để phân biệt vị trí cột, aggregate-only, dimension, grouping, HAVING,
   ORDER BY, pagination và các cấu trúc được duyệt; từ chối cú pháp không hỗ trợ.
6. Tích hợp role từ session tin cậy qua `PolicySQLGate`, `SecureSqlTool`,
   `SQLiteExecutor`; bảo đảm mọi query, count và page chạy trong cùng policy-aware boundary.
7. Thiết kế assignment enforcement và output suppression/history ở query service hoặc tầng DB;
   không dùng LLM prompt thay cho enforcement.
8. Thêm fixture schema không chứa dữ liệu nhạy cảm và test cho từng role/cột, row scope,
   aggregate leaks, repeated query, wrapper/count, SQLite authorizer và giữ nguyên hành vi
   system role. Chỉ xem xét bật quyền sau review bảo mật và phê duyệt nghiệp vụ.

## 8. Phạm vi và tài liệu cần xử lý sau

Tài liệu này là proposal cho `financial.sqlite` được chọn theo quyết định người dùng. Nó không
phê duyệt ma trận và không khẳng định provenance/license đã xác minh. `SECURITY_WORKPLAN.md`
§12 vẫn ghi quyết định cũ BIRD Mini-Dev Financial và các role `teller`/`credit`/`risk`; cần
được cập nhật trong task tài liệu riêng sau khi nhóm duyệt đề xuất, không mở rộng sửa trong
task này. Tài liệu [`BUSINESS_ROLE_POLICY_DESIGN.md`](./BUSINESS_ROLE_POLICY_DESIGN.md) là
phân tích trước đó; các đoạn coi BIRD là phương án ưu tiên đã được đánh dấu là lịch sử/
superseded.

Không có policy executable, runtime authorization, authentication, SQL gate, executor, API
query hoặc test code nào được thay đổi trong task proposal này. Không có tuyên bố quyền đã
được triển khai hay bảo mật đã được xác minh.
