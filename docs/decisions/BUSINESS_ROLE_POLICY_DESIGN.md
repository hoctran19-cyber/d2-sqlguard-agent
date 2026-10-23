# Thiết kế policy và thống nhất schema cho business role

**Trạng thái: đang review thiết kế; chưa được phê duyệt và chưa được thực thi.** Tài liệu này
ghi lại bằng chứng trong repository và các quyết định cần có trước khi triển khai. Tài liệu
không cấp quyền SQL cho `operator`, `analyst` hoặc `credit_officer`, cũng không phê duyệt
matrix tham chiếu hiện có trên web làm policy production.

## Khuyến nghị tổng quan

Ưu tiên **BIRD Mini-Dev Financial trên SQLite (Phương án A)** làm ứng viên schema chuẩn của
dự án, với điều kiện nhóm xác nhận quyết định dự án trước đó và kiểm tra database thực tế.
Căn cứ gồm quyết định Q1 tại §12.1 của workplan về BIRD Financial SQLite, schema/policy hướng
theo BIRD `bird_financial_v1`, cùng benchmark và pilot BIRD Financial. Đây là khuyến nghị,
**không phải quyết định schema cuối cùng**: checkout này không có `financial.sqlite`, và
workplan cho biết chỉ có file thực tế trên máy một thành viên trong nhóm.

Không ánh xạ ba định danh business role sang `teller`, `credit` hoặc `risk`. Repository không
có bằng chứng phê duyệt các tương đương đó. Matrix web là một matrix riêng, mô tả schema
SQLite có cột synthetic; các tài liệu Vault mà matrix viện dẫn không có trong repository và
database thực tế chưa được kiểm tra. Nhóm cần chọn schema chuẩn, xác nhận nguồn gốc/phiên bản
và duyệt matrix role dựa trên đúng schema đó trước khi bật SQL cho business role. Cho tới khi
các việc này hoàn tất, tiếp tục từ chối API dữ liệu của business role.

## Bằng chứng đã kiểm tra và giới hạn

| Nguồn | Bằng chứng trong repository | Điều chưa thể kết luận |
| --- | --- | --- |
| `docs/threat-model/SECURITY_WORKPLAN.md` §12 | §12.1 ghi Q1 “BIRD Mini-Dev Financial dạng SQLite” được chốt ngày 21/10; Q2/Q3 được đánh dấu rõ là lệch với matrix web xuất hiện sau đó. §12.2 mô tả policy `teller`/`credit`/`risk` ngày 19/10. §12.3 N-e yêu cầu thống nhất hai matrix và database, đồng thời đặt câu hỏi file SQLite nội bộ là BIRD gốc hay bản dẫn xuất có sáu cột synthetic. | Không chứng minh nội dung hoặc provenance của database cài trên máy một thành viên. |
| `src/sqlguard/security/policies/bird_financial_v1.json` và `src/sqlguard/security/policy.py` | Có schema hướng BIRD theo phiên bản, grant cột cụ thể cho `teller`, `credit`, `risk`, khóa ngoại, hàm SQL, giới hạn và ba canary `client.national_id`. `RolePolicy` kiểm tra grant role và khóa ngoại theo schema khai báo. | Không có `operator`, `analyst`, `credit_officer`; schema có overlay và chưa được xác minh với database web nội bộ. Đây cũng không phải policy mặc định: `DEFAULT_POLICY` là `d2_synthetic_v1`. |
| `src/sqlguard/web/role_reference.py` và `tests/unit/test_web_roles.py` | Có matrix tham chiếu riêng gồm 8 bảng/61 cột cho `operator`, `analyst`, `credit_officer`; test kiểm độc lập allowlist và số lượng. Module ghi rõ matrix chỉ để hiển thị, chưa được thực thi. | Các tài liệu Vault “2026-10-20” và “2026-10-22” được viện dẫn không có trong repository. Test chỉ chứng minh code và reference khớp nhau, không chứng minh grant nghiệp vụ đã được duyệt hoặc khớp database đang dùng. |
| `src/sqlguard/web/database.py`, `src/sqlguard/web/query_service.py` | Web dùng `SQLGUARD_FINANCIAL_DB` hoặc mặc định `data/bird/financial.sqlite`; mở database chỉ đọc và bật `query_only`. Schema bảng/cột được introspect từ file. | File database không có trong checkout nên chưa thể xác minh bảng, cột, metadata và revision thực tế. |
| `evaluation/datasets/financial/README.md`, `evaluation/bird_pilot.py`, `tests/unit/test_bird_pilot.py` | Các task D2 Financial dùng tên business role và tham chiếu BIRD source/Gold; suite ghi policy mới được mô tả, chưa enforce. Pilot hỗ trợ schema/query source PostgreSQL hoặc SQLite tương thích, runtime role dựa trên policy và kiểm tra danh tính DB cục bộ. | Nhãn role trong benchmark không phải quyết định phân quyền. Tài liệu dataset nói SQLite reference không phải expected data PostgreSQL và snapshot/provenance còn pending hoặc chưa xác minh. |
| Tìm kiếm `*.sqlite` trong workspace | Không tìm thấy file SQLite nào trong checkout này. | Không cho biết database trên máy thành viên khác hoặc deployment bên ngoài có nội dung gì. |

## Các schema ứng viên

### Phương án A — BIRD Financial SQLite (ứng viên ưu tiên, chờ xác minh)

**Lý do đây là ứng viên phù hợp hơn với định hướng dự án:** Q1 trong workplan ghi đây là
database dự án đã chọn; policy bảo mật hiện tại hướng theo BIRD; repository có benchmark và
pilot BIRD Financial; `FinancialDatabase` cũng mặc định dùng đường dẫn
`data/bird/financial.sqlite`. Phương án này thống nhất policy, đánh giá và định hướng dự án tốt
hơn việc coi một schema dẫn xuất chưa xác minh là chuẩn.

Policy JSON khai báo các bảng/cột sau (bao gồm cả overlay của policy):

| Bảng | Các cột khai báo |
| --- | --- |
| `account` | `account_id`, `district_id`, `frequency`, `date` |
| `card` | `card_id`, `disp_id`, `type`, `issued` |
| `client` | `client_id`, `gender`, `birth_date`, `district_id`, `national_id`, `note` |
| `disp` | `disp_id`, `client_id`, `account_id`, `type` |
| `district` | `district_id`, `a2`–`a16` |
| `loan` | `loan_id`, `account_id`, `date`, `amount`, `duration`, `payments`, `status` |
| `order` | `order_id`, `account_id`, `bank_to`, `account_to`, `amount`, `k_symbol` |
| `trans` | `trans_id`, `account_id`, `date`, `type`, `operation`, `amount`, `balance`, `k_symbol`, `bank`, `account`, `note` |

Trường `status` trong policy JSON mô tả `client.national_id`, `client.note` và `trans.note` là
các cột overlay bảo mật. Đặc biệt, điều đó **không chứng minh** `national_id` tồn tại trong
bản BIRD upstream chưa chỉnh sửa. Cần kiểm tra database tại chỗ và đối chiếu schema/revision
chính xác với policy trước khi dựa vào danh sách này.

Workplan nói matrix bảo mật cho ba role *khác* này được duyệt ngày 19/10; grant thực tế trong
`bird_financial_v1.json` như sau:

| Bảng | `teller` (chỉ để đối chiếu; không đồng nghĩa `operator`) | `credit` (không đồng nghĩa `credit_officer`) | `risk` (không đồng nghĩa `analyst`) |
| --- | --- | --- | --- |
| `account` | `account_id`, `district_id`, `frequency`, `date` | giống `teller` | giống `teller` |
| `card` | `card_id`, `disp_id`, `type`, `issued` | giống `teller` | giống `teller` |
| `client` | `client_id`, `gender`, `district_id`, `note` | `client_id`, `gender`, `birth_date`, `district_id`, `note` | `client_id`, `gender`, `district_id`, `note` |
| `disp` | `disp_id`, `client_id`, `account_id`, `type` | giống `teller` | giống `teller` |
| `district` | tất cả cột khai báo: `district_id`, `a2`–`a16` | giống `teller` | giống `teller` |
| `loan` | từ chối (không có grant bảng) | tất cả cột khai báo | tất cả cột khai báo |
| `order` | `order_id`, `account_id`, `amount`, `k_symbol` | giống `teller` | tất cả cột khai báo, gồm `bank_to` và `account_to` |
| `trans` | `trans_id`, `account_id`, `date`, `type`, `operation`, `amount`, `balance`, `k_symbol`, `note` | giống `teller` | tất cả cột khai báo, gồm `bank` và `account` |

Cả ba role đều bị từ chối `client.national_id`; policy có ba canary cho cột này. Policy cấp
`client.note` và `trans.note` cho cả ba role. Tuy nhiên, policy không tự enforce yêu cầu trong
workplan rằng ghi chú là văn bản tự do không đáng tin cậy; làm sạch output/xử lý injection là
biện pháp riêng, không khiến nội dung ghi chú trở nên đáng tin.

**Thay đổi/phê duyệt cần cho Phương án A:** xác minh marker, revision, bảng và cột trong
database SQLite thực tế; chốt danh sách grant của ba business role trên đúng schema đó; quyết
định overlay bảo mật nào tồn tại trong DB được chọn; ghi nhận provenance và licensing của
nguồn upstream/quá trình chuyển đổi nội bộ; sau đó tạo policy nghiệp vụ riêng đã được duyệt
(hoặc phiên bản BIRD policy được review rõ ràng), không âm thầm tái sử dụng grant cũ. Giữ
`admin` và `evaluator` là system role riêng biệt.

### Phương án B — schema tham chiếu web hiện tại

Matrix web mô tả 8 bảng và 61 cột:

| Bảng | Các cột tham chiếu |
| --- | --- |
| `client` | `client_id`, `gender`, `birth_date`, `district_id`, `id_number`, `full_name`, `address` |
| `disp` | `disp_id`, `client_id`, `account_id`, `type` |
| `account` | `account_id`, `district_id`, `frequency`, `date`, `service_note` |
| `trans` | `trans_id`, `account_id`, `date`, `type`, `operation`, `amount`, `balance`, `k_symbol`, `bank`, `account` |
| `order` | `order_id`, `account_id`, `bank_to`, `account_to`, `amount`, `k_symbol`, `note` |
| `card` | `card_id`, `disp_id`, `type`, `issued`, `placeholder` |
| `loan` | `loan_id`, `account_id`, `date`, `amount`, `duration`, `payments`, `status` |
| `district` | `district_id`, `A2`–`A16` |

Matrix này khớp với định danh business role và test web. Sáu cột synthetic được workplan nhắc
tới là `client.id_number`, `client.full_name`, `client.address`, `account.service_note`,
`order.note`, `card.placeholder`. Matrix còn khác schema BIRD policy: ví dụ có
`client.id_number` thay vì `client.national_id`, có `client.full_name`/`address` và
`card.placeholder`, nhưng không có `client.note` hay `trans.note`.

Grant cụ thể trong reference:

| Role | Bảng | Các cột được matrix web đánh dấu cho phép |
| --- | --- | --- |
| `operator` | `client` | `client_id`, `district_id`, `full_name`, `address` |
|  | `disp` | `disp_id`, `client_id`, `account_id`, `type` |
|  | `account` | `account_id`, `district_id`, `frequency`, `date`, `service_note` |
|  | `trans` | `trans_id`, `account_id`, `date`, `type`, `operation`, `amount`, `balance`, `k_symbol`, `bank`, `account` |
|  | `order` | `order_id`, `account_id`, `bank_to`, `account_to`, `amount`, `k_symbol`, `note` |
|  | `card` | `card_id`, `disp_id`, `type`, `issued` |
|  | `loan` | không có |
|  | `district` | `district_id`, `A2`, `A3` |
| `analyst` | `client` | `client_id` (khóa tổng hợp), `gender`, `district_id` (chiều tổng hợp) |
|  | `disp` | `client_id`, `account_id` (khóa tổng hợp), `type` (chiều tổng hợp) |
|  | `account` | `account_id` (khóa tổng hợp), `district_id`, `frequency`, `date` (chiều tổng hợp) |
|  | `trans` | `trans_id`, `account_id` (khóa tổng hợp), `date`, `type`, `operation`, `k_symbol` (chiều tổng hợp), `amount` (số liệu tổng hợp) |
|  | `order` | không có |
|  | `card` | không có |
|  | `loan` | không có |
|  | `district` | `district_id`, `A2`, `A3` (chiều tổng hợp); `A4`, `A10`, `A11`, `A12`, `A13` (số liệu tổng hợp) |
| `credit_officer` | `client` | `client_id`, `full_name`, `district_id` |
|  | `disp` | `disp_id`, `client_id`, `account_id`, `type` |
|  | `account` | `account_id`, `district_id`, `frequency`, `date` |
|  | `trans` | `trans_id`, `account_id`, `date`, `type`, `operation`, `amount`, `balance`, `k_symbol` |
|  | `order` | `order_id`, `account_id`, `amount`, `k_symbol` |
|  | `card` | không có |
|  | `loan` | `loan_id`, `account_id`, `date`, `amount`, `duration`, `payments`, `status` |
|  | `district` | `district_id`, `A2`, `A3`, `A11`, `A12`, `A13` |

Trong `role_reference.py`, mọi cột không liệt kê đều bị đánh dấu từ chối; test ghim tổng số
cột cho phép/từ chối lần lượt là 37/24 với operator, 25/36 với analyst và 36/25 với credit
officer. Nhãn role mô tả operator hỗ trợ/vận hành, analyst phân tích, credit officer quản lý
tín dụng/khoản vay; nhưng tài liệu nghiệp vụ được viện dẫn nằm ngoài repository nên không thể
dùng ở đây làm căn cứ đã review.

**Thay đổi/phê duyệt cần cho Phương án B:** cung cấp database thực tế và xác minh schema,
revision, provenance; xác định cột synthetic có dữ liệu thật, dữ liệu dẫn xuất hay chỉ là giá
trị thử nghiệm; duyệt các grant đã liệt kê; tạo policy phiên bản riêng khớp chính xác
database. Không thêm tên cột này vào policy trước khi xác nhận chúng tồn tại trong DB. Ghi
chú “synthetic” sáu cột trong workplan không thay thế việc kiểm tra database.

## Trạng thái thiết kế theo từng role

Các quyền dưới đây là bản chép từ matrix web, **không phải grant đã được phê duyệt**. “Không
liệt kê” chỉ có nghĩa là bị từ chối theo matrix tham khảo đó. Hiện tại, business role không có
quyền SQL hiệu lực trong ứng dụng web.

### `operator`

- **Mục đích được mô tả:** vận hành và hỗ trợ người dùng (theo `ROLE_LABELS`); matrix viện dẫn
  mô tả role hỗ trợ/vận hành. Repository không có chi tiết nhiệm vụ hoặc căn cứ least privilege.
- **Quyền đọc theo schema reference:** `client(client_id, district_id, full_name, address)`;
  `disp(disp_id, client_id, account_id, type)`;
  `account(account_id, district_id, frequency, date, service_note)`;
  `trans(trans_id, account_id, date, type, operation, amount, balance, k_symbol, bank, account)`;
  `order(order_id, account_id, bank_to, account_to, amount, k_symbol, note)`;
  `card(card_id, disp_id, type, issued)`;
  `district(district_id, A2, A3)`. Không có cột `loan` nào được liệt kê.
- **Bị từ chối theo reference:** `client.gender`, `birth_date`, `id_number`; `card.placeholder`;
  toàn bộ cột `loan`; và các cột `district` không liệt kê (`A4`–`A16`). Các cột khác không có
  trong bảng trên cũng bị từ chối.
- **Dạng truy vấn:** reference đánh dấu các cột là `read`, không yêu cầu tổng hợp. Reference
  không nêu rõ có cho phép JOIN, truy vấn lồng, GROUP BY hoặc hàm tổng hợp theo role không.
  Giới hạn tổng quát của policy engine là chỉ đọc, không phải quy tắc query-shape riêng cho
  operator. Không coi nhãn `read` là phê duyệt truy cập bản ghi chi tiết hoặc phạm vi JOIN
  trước khi được xác nhận. Reference cũng không có ranh giới theo nhân viên/chi nhánh được giao.

### `analyst`

- **Mục đích được mô tả:** phân tích và báo cáo (theo nhãn role). Reference gọi phạm vi này là
  aggregate-only và nêu các điều kiện bên dưới; văn bản phê duyệt gốc không có trong repository.
- **Cột theo schema reference:** chỉ các khóa, chiều, số liệu tổng hợp liệt kê ở Phương án B.
  Không có cột `order`, `card`, `loan`. Reference không cấp tên, địa chỉ, `id_number`, ngày
  sinh, `trans.balance`, thông tin ngân hàng/tài khoản đối tác hoặc chi tiết thẻ/khoản vay.
- **Bản ghi chi tiết:** **reference nói không trả dữ liệu từng dòng**. Tuy nhiên, nhãn cột tự
  nó không ngăn được `SELECT client_id`, `GROUP BY trans_id`, lọc theo ID cá nhân, `SUM` trên
  một dòng hoặc làm lộ thông tin qua nhóm nhỏ. Vì vậy, repository không chứng minh quy tắc
  aggregate-only đã được thực thi, cũng không chứng minh analyst chỉ có thể xem kết quả tổng hợp.
- **Định danh:** reference không cấp trực tiếp tên/địa chỉ và các cột định danh synthetic.
  Tuy nhiên, vẫn cấp `client_id` và các khóa khác để JOIN/COUNT; nếu không có kiểm soát query
  và output bổ sung, vẫn có thể tái nhận diện gián tiếp và tạo tổng hợp theo từng khách hàng.
- **Hàm:** policy bảo mật hiện tại liệt kê `Count`, `Sum`, `Avg`, `Min`, `Max`; SQL gate nhận
  diện hàm theo policy. Việc các hàm có mặt trong BIRD policy **không** đồng nghĩa chúng đã
  được phê duyệt cho analyst, cũng không thực thi aggregate-only. Web reference dùng nhãn khóa/
  chiều/số liệu nhưng không định nghĩa đầy đủ ngữ pháp hàm được phép.
- **Quyết định còn thiếu:** có cấm hoàn toàn output chi tiết không; cho phép hàm tổng hợp nào
  (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`); cho phép chiều nhóm/bucket nào; khóa có thể trả ra hay
  chỉ dùng nội bộ để JOIN/COUNT; ngưỡng nhóm tối thiểu và cách suppression; có cấm lọc theo ID
  từng bản ghi không; và cách ngăn aggregate một cá nhân hoặc phép sai phân giữa nhiều truy vấn.
  Cho tới khi các quy tắc được duyệt và có thể thực thi, từ chối SQL của analyst.

### `credit_officer`

- **Mục đích được mô tả:** quản lý tín dụng/khoản vay (theo nhãn role); reference cấp các cột
  khoản vay. Căn cứ công việc chi tiết nằm trong tài liệu ngoài repository.
- **Quyền đọc theo schema reference:** `loan(loan_id, account_id, date, amount, duration, payments, status)`;
  `account(account_id, district_id, frequency, date)`;
  `disp(disp_id, client_id, account_id, type)`;
  `client(client_id, full_name, district_id)`;
  `trans(trans_id, account_id, date, type, operation, amount, balance, k_symbol)`;
  `order(order_id, account_id, amount, k_symbol)`;
  `district(district_id, A2, A3, A11, A12, A13)`. Không có cột `card` nào được liệt kê.
- **Bị từ chối theo reference:** toàn bộ cột `card`; `client.gender`, `birth_date`, `id_number`,
  `address`; `trans.bank`, `trans.account`; `order.bank_to`, `order.account_to`, `order.note`;
  `district.A4`–`A10` và `A14`–`A16`; cùng các cột khác không được liệt kê.
- **Dạng truy vấn:** được đánh dấu `read`, không phải aggregate-only. Nhưng điều này không quyết
  định quyền có giới hạn theo khách hàng/tài khoản được giao hay không, cũng không chứng minh
  có căn cứ cho quyền đọc mọi bản ghi khoản vay. Reference không nêu rõ quyền JOIN, truy vấn
  lồng, GROUP BY hay hàm tổng hợp cho role này; nhãn chỉ đọc không phải đặc tả query-shape.

## Danh mục dữ liệu nhạy cảm (phụ thuộc schema)

Đây là rà soát dữ liệu cần bảo vệ, không phải danh sách cấp quyền. Tên dưới đây thuộc schema
được khai báo trong từng nguồn; không giả định mọi cột đều tồn tại trong database thực tế đã
chọn.

| Nhóm dữ liệu | Tên trong BIRD policy | Tên trong web reference | Ghi chú thiết kế |
| --- | --- | --- | --- |
| Định danh trực tiếp / nhân khẩu học | `client.national_id` (overlay), `client.birth_date`, `client.gender`, `client.client_id` | `client.id_number` (synthetic), `client.full_name` (synthetic), `client.address` (synthetic), `client.birth_date`, `client.gender`, `client.client_id` | Có thể nhận dạng hoặc mô tả rõ cá nhân. `client_id` là khóa liên kết, không phải ẩn danh. Policy BIRD hiện tại có canary và từ chối `national_id`; web reference dùng tên cột định danh synthetic khác. |
| Định danh tài khoản / quan hệ | `account.account_id`, `disp.client_id`, `disp.account_id`, `card.disp_id` | Các cột cùng tên, thêm `account.service_note` (synthetic) | Khóa có thể liên kết để lộ quyền sở hữu/hoạt động tài khoản khi JOIN. Cả hai allowlist đều không giới hạn phạm vi theo phân công. |
| Chi tiết giao dịch / thanh toán | `trans.amount`, `balance`, `date`, `operation`, `bank`, `account`; `order.amount`, `bank_to`, `account_to` | Các cột cùng tên, thêm `order.note` (synthetic); web reference không khai báo `trans.note` | Số tiền, số dư, thời điểm giao dịch và định danh ngân hàng/tài khoản đối tác đều nhạy cảm. Grant BIRD hiện tại khác nhau: teller/credit không có cột tài khoản/ngân hàng đối tác, risk có; web reference cấp chúng cho operator nhưng từ chối credit officer. Đây là mâu thuẫn cần phê duyệt. |
| Dư nợ tín dụng | `loan.amount`, `payments`, `duration`, `status`, `account_id`, `loan_id` | Các cột cùng tên | Dư nợ, điều khoản trả nợ/trạng thái và ID liên kết đều nhạy cảm. Web reference cấp các cột này cho credit officer; BIRD policy cấp cho `credit` và `risk`, không cấp cho `teller`. Chưa được ánh xạ role. |
| Dữ liệu thẻ | `card.card_id`, `disp_id`, `type`, `issued` | Các cột cùng tên, thêm `card.placeholder` (token synthetic) | ID, loại và thông tin phát hành cần được duyệt phạm vi. Reference mô tả placeholder không phải số thẻ/CVV/PIN thật, nhưng nội dung và sự tồn tại trong DB chưa xác minh. |
| Ghi chú / văn bản tự do không đáng tin | `client.note`, `trans.note` (overlay) | `account.service_note`, `order.note` (synthetic) | Ghi chú có thể chứa dữ liệu cá nhân hoặc văn bản prompt injection. BIRD hiện cấp hai cột note cho cả ba role cũ. Làm sạch văn bản không thay thế kiểm tra quyền cột hoặc xử lý dữ liệu không đáng tin. |
| Thuộc tính khu vực | `district.a2`–`a16` | `district.A2`–`A16` | `a11`/`A11` là lương trung bình khu vực; các thống kê nhân khẩu học/kinh tế khác có thể nhạy cảm ở nhóm địa lý nhỏ. Cần khớp chữ hoa/thường và schema với DB thực tế. |

Từ chối đọc một cột có thể ngăn truy vấn trực tiếp trường đó, nhưng không tự ngăn suy luận qua
JOIN, điều kiện lọc, đếm số dòng hay tổng hợp được phép. Đây là các kiểm soát query-shape và
chống lộ thông tin riêng.

## Đánh giá khả năng thực thi của policy engine

| Quy tắc/kiểm soát | Khả năng hiện tại | Phân loại / thiếu sót |
| --- | --- | --- |
| Allowlist chính xác role → bảng → cột | `RolePolicy` lưu và kiểm tra tính nhất quán; `PolicySQLGate` kiểm tra tham chiếu role/bảng/cột; `SQLiteExecutor` độc lập cho phép đọc bảng/cột trên từng kết nối SQLite. | **Có thể thực thi** grant thông thường sau khi policy được duyệt, khớp DB thực tế và caller nhận role từ session đáng tin. |
| Danh tính đáng tin gắn với role | `SecurityContext` được thiết kế để nhận context đáng tin từ backend; `SecureSqlTool` lấy role từ context này và chỉ nhận đối số SQL. | **Có thể thực thi trong secure runtime.** Web phải tạo context từ session đã xác thực phía server. Không nhận role từ request/LLM. Query path web hiện không dùng runtime này cho business role. |
| Cột bị cấm trong SELECT/filter/group/order/join/hàm | AST gate kiểm tra tham chiếu cột ngoài phần projection; SQLite authorizer trực tiếp từ chối đọc cột không được cấp. Cơ chế auto-partial có thể bỏ cột hiển thị bị cấm, nhưng không thể sửa an toàn các vị trí sử dụng khác bằng cách chỉ lọc UI. | **Có thể thực thi với cú pháp được hỗ trợ** bằng policy gate và executor. Cần quyết định endpoint business role nên từ chối toàn bộ hay cho phép tự thu hẹp một phần. |
| Quyền JOIN | Gate giới hạn JOIN vào cặp khóa ngoại có thể đọc và giới hạn số JOIN. SQLite authorizer từ chối `NATURAL`/`USING` vì SQLite có thể không báo các cột được dùng để so sánh. | **Có thể thực thi với tập con JOIN hỗ trợ**; không làm yếu một trong hai biện pháp. |
| Subquery, CTE, UNION/INTERSECT/EXCEPT | Gate hiện từ chối các dạng này. | **Có thể từ chối ngay.** Nếu hỗ trợ về sau, cần kiểm tra scope/cột đệ quy và test; không bao giờ chỉ dựa vào kiểm tra query ngoài. |
| Ghi dữ liệu, DDL, PRAGMA, ATTACH, catalog, hàm không allowlist | Gate giới hạn dạng SQL; SQLite authorizer từ chối mọi thao tác ngoài SELECT/đọc/hàm được phép; kết nối mở chỉ đọc và bật `query_only`. | **`SQLiteExecutor` có thể thực thi.** Giữ cả AST gate lẫn DB authorizer; không lớp nào thay thế lớp còn lại. |
| Allowlist hàm aggregate | `RolePolicy.functions`, gate và SQLite executor có allowlist các hàm phổ biến trong policy hiện tại. | **Có thể cho phép/từ chối theo tên hàm**, nhưng không chứng minh output chỉ là aggregate, không định danh được cá nhân hoặc đạt ngưỡng nhóm. |
| Chế độ dùng khóa/chiều/số liệu của analyst | `RolePolicy` chỉ lưu tập hợp cột được phép theo bảng. Không có chế độ cột “chỉ dùng JOIN”, “chỉ dùng group/filter” hay “aggregate-only”. | **Cần mở rộng policy và SQL gate.** Kiểm tra ngữ cảnh AST; chặn projection trực tiếp khóa và GROUP BY khóa cá nhân; enforce quy tắc bucket/số liệu sau khi được duyệt. Không dựa vào prompt LLM. |
| Ngưỡng nhóm tối thiểu, suppression, sai phân | `RolePolicy`, SQL gate và SQLite authorizer không có quy tắc này. | **Cần hỗ trợ ở query service/business logic** trên kết quả aggregate đã parse/typed, hoặc cơ chế riêng ở DB đã được review; phải chốt ngưỡng và complementary suppression trước. Nguy cơ sai phân qua truy vấn lặp có thể cần kiểm soát có trạng thái. |
| Giới hạn theo phân công/quyền sở hữu | Allowlist cột hiện tại và web DB layer không gắn user với tập khách hàng/tài khoản/chi nhánh. | **Cần dữ liệu nghiệp vụ và kiểm soát row-level ở query service/DB.** Không thể triển khai an toàn chỉ từ tên role hoặc predicate SQL tự do do user cung cấp. |
| Wrapper phân trang / đếm tổng số dòng | `FinancialDatabase.run_page` bọc SQL nhận vào thành `SELECT COUNT(*) FROM (...)` và `SELECT * FROM (...) LIMIT/OFFSET` riêng; dùng kết nối chỉ đọc nhưng không cài authorizer của `SQLiteExecutor`. `/api/sql` hiện dùng `ReadOnlySQLGate` chỉ kiểm tra tên bảng trước wrapper; đường NL web cũng dùng gate chỉ kiểm tra bảng và `FinancialDatabase`. | **Web path hiện không được policy hiện tại bảo vệ.** Tích hợp sau này phải authorize AST gốc và chỉ thực thi SQL đã normalize qua ranh giới có policy. Truy vấn đếm và truy vấn trang phải đi qua cùng executor đã authorize hoặc wrapper đáng tin được đặt bên trong executor; cần đánh giá riêng rò rỉ số lượng dòng. Không chỉ kiểm tra query gốc rồi chạy wrapper/SQL thay thế chưa được kiểm tra. |
| Schema DB thực tế bị lệch | `RolePolicy.from_dict` kiểm tra grant theo schema khai báo; pilot có kiểm tra marker/schema DB cho workflow BIRD. `FinancialDatabase` web introspect tên thật nhưng không so sánh với role policy. | **Cần preflight/integration khi triển khai.** Ghim danh tính/revision database, so sánh chính xác bảng/cột và từ chối khi không khớp. |

`SecureSqlTool` còn dùng SQL đã normalize, giới hạn dòng/byte, sanitize, kiểm tra canary và
audit. Các biện pháp này hữu ích nhưng không giải quyết các quy tắc aggregate analyst hoặc
phân công dữ liệu còn thiếu. `PolicySQLGate` hiện parse/normalize tập con D2 theo dialect
PostgreSQL, trong khi `FinancialDatabase` parse/thực thi SQLite; khi tích hợp web cần xác minh
tính tương thích dialect, không giả định SQL đã normalize có thể chạy tương đương.

## Các câu hỏi cần nhóm phê duyệt rõ ràng

1. **Database chuẩn:** Xác nhận chọn Phương án A (BIRD Mini-Dev Financial SQLite) hay Phương
   án B (bản dẫn xuất web). Ai sở hữu quyết định và version/hash có thẩm quyền?
2. **Bằng chứng database:** Cung cấp file thực tế hoặc quy trình tải/chuyển đổi có thể tái lập;
   ghi database ID, source revision, chính xác bảng/cột trong `sqlite_master`, và xác định từng
   overlay/cột synthetic có tồn tại cũng như nội dung của chúng. File trên máy nhóm là BIRD
   gốc hay bản dẫn xuất nêu trong N-e?
3. **Matrix business role:** Trên schema đã chọn, duyệt allowlist bảng/cột chính xác và căn cứ
   nhiệm vụ cho từng role. Xác nhận rõ không có ánh xạ ngầm `operator`→`teller`,
   `analyst`→`risk`, `credit_officer`→`credit`.
4. **Operator:** Có cần đọc bản ghi client/account/transaction chi tiết không? Có giới hạn
   theo khách hàng/tài khoản/chi nhánh được giao không? Có căn cứ cấp `full_name`, `address`,
   `bank`, `account`, `bank_to`, `account_to` không? Có cần các cột note synthetic không?
5. **Analyst:** Có cấm hoàn toàn bản ghi chi tiết không? Aggregate nào được phép
   (`COUNT`, `SUM`, `AVG`, `MIN`, `MAX`)? Khóa nào chỉ dùng nội bộ, khóa nào có thể trả ra?
   Cho phép chiều/bucket nào? Ngưỡng nhóm tối thiểu, suppression và chống sai phân là gì? Có
   cho lọc theo khóa từng bản ghi không?
6. **Credit officer:** Có được đọc `loan.*` trên mọi account hay chỉ hồ sơ được phân công?
   `client.full_name` có cần thiết không? Có cần giao dịch liên kết và thông tin thanh toán
   đối tác không? Xác nhận có từ chối định danh bank/account đối tác và dữ liệu thẻ không.
7. **Cột nhạy cảm và overlay:** Cột định danh, account, transaction, credit và văn bản tự do
   nào được phân loại nhạy cảm? Có role nghiệp vụ nào được đọc `client.note`/`trans.note`
   (BIRD) hoặc `account.service_note`/`order.note` (web reference) không? Overlay nào chỉ dành
   cho lab và phải cấm trong production?
8. **Mô hình truy cập:** Xác nhận authentication demo theo process chỉ phù hợp demo local hay
   không. Identity provider/user store production nào và quy trình gán role có audit nào là
   nguồn role đáng tin phía server?
9. **Phân trang/đếm:** Business role có được xem số dòng/tổng số kết quả không? Có cần
   suppression hoặc giới hạn các con số này không? Xác nhận wrapper phải chạy trong cùng ranh
   giới policy-aware với query đã được validate.

## Trình tự đề xuất cho task triển khai kế tiếp

1. Lấy phê duyệt bằng văn bản về schema chuẩn, provenance/version dữ liệu, grant từng role,
   quy tắc query-shape/privacy của analyst và phạm vi phân công. Giữ SQL business role bị tắt
   cho tới khi đáp ứng các điều kiện này.
2. Kiểm tra trực tiếp DB nội bộ đã được duyệt; đối chiếu bảng/cột thực tế, phiên bản SQLite,
   metadata marker và revision với schema được duyệt. Tạo fixture test xác định cho schema đó;
   không commit dữ liệu production riêng tư.
3. Tạo policy có version riêng cho các định danh business role đã duyệt. Giữ `admin`/
   `evaluator` là system role riêng và không sửa `bird_financial_v1` để ép một ánh xạ chưa được
   duyệt. Kiểm tra grant và khóa ngoại khi load policy.
4. Chỉ mở rộng policy/gate cho quyền analyst theo ngữ cảnh và kiểm soát phân công đã duyệt.
   Từ chối cú pháp không hỗ trợ hoặc mơ hồ; không dùng prompt làm lớp enforce duy nhất.
5. Nối role từ session server đã xác thực vào `PolicySQLGate`, `SecureSqlTool` và
   `SQLiteExecutor`. Đảm bảo SQL thủ công và SQL từ NL dùng cùng trusted context và policy.
6. Thiết kế lại hoặc bọc an toàn quá trình phân trang/đếm để cả truy vấn đếm và truy vấn trang
   dùng query đã normalize, validate và cùng authorizer theo role; giới hạn và đánh giá rò rỉ
   cardinality. Giữ SQLite read-only, authorizer và từ chối `NATURAL`/`USING`.
7. Bổ sung test xác định cho mọi bảng/cột và role đã duyệt, cột nhạy cảm, predicate/JOIN/hàm,
   aggregate output và suppression của analyst, phân công, injection/ghi/SQLite operation
   không hỗ trợ, wrapper/count, session thiếu/role lạ, cùng tính tương thích admin/evaluator.
   Chạy regression web/security/MCP trước khi cân nhắc bật quyền.
8. Sinh nội dung Info web từ executable policy đã duyệt hoặc test đối chiếu Info với policy đó
   để tài liệu không lệch. Review việc che lỗi và audit.

Task thiết kế này không sửa runtime authorization, authentication, gate, executor hay API
query.
