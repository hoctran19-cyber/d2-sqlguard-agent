
## 1. Bối cảnh

**Roles thay đổi so với proposal**:

| Proposal | D2             |
| -------- | -------------- |
| Sales    | Operator       |
| Teller   | Analyst        |
| Operator | Credit Officer |

**Tình huống cụ thể:** một ngân hàng có tài khoản thanh toán, khách hàng là chủ tài khoản hoặc người được quyền sử dụng, thẻ gắn với quan hệ đó, giao dịch, lệnh thanh toán định kỳ và khoản vay. Ba nhân viên sử dụng SQLGuard để lấy thông tin phục vụ công việc; tác nghiệp ghi dữ liệu, xác minh danh tính và quyết định nghiệp vụ diễn ra ở quy trình/hệ thống khác.

Ví dụ cùng một tài khoản: operator giải thích giao dịch và lệnh thanh toán cho khách hàng; analyst đưa hoạt động của tài khoản vào thống kê theo vùng/tháng, không xuất hồ sơ cá thể; credit_officer xem khoản vay và giao dịch liên quan để lập danh sách cần kiểm tra. Không có thứ bậc “credit cao hơn operator”: mỗi role có phạm vi riêng.

### Quy ước chung của các permission matrix

- **Đọc:** được dùng cột trong truy vấn chỉ đọc, gồm trả chi tiết theo policy hiện hành.
- **TH–khóa:** analyst chỉ dùng khóa cá thể cho JOIN/đếm, không xuất danh sách ID cá thể hoặc GROUP BY ID để lách tổng hợp.
- **TH–chiều:** analyst được dùng chiều phân tích trong truy vấn tổng hợp, ví dụ vùng/tháng/loại giao dịch. Không tự cho phép xuất từng row nguồn.
- **TH–số liệu:** analyst được dùng số liệu để tính chỉ tiêu tổng hợp hoặc đối chiếu chỉ số vùng; không xuất giao dịch cá thể.
- **Cấm:** không SELECT, lọc, JOIN, sắp xếp, dùng trong biểu thức/subquery hoặc đọc rồi che. Cấm toàn bảng bao gồm mọi cột của bảng đó.
- Mọi role chỉ đọc; không INSERT/UPDATE/DELETE/DDL. Cột mới hoặc cột không được liệt kê mặc định bị cấm. `SELECT *` ở bảng chỉ cấp một phần phải được kiểm đầy đủ hoặc từ chối, không âm thầm đổi nghĩa câu hỏi.
- Các quyền “Đọc” là quyền bảng/cột, **chưa có giới hạn theo nhân viên phụ trách**. “Trong phạm vi được giao” là yêu cầu nghiệp vụ chưa có dữ liệu phân công và chưa được chứng minh enforce.
- Các bảng bên dưới mô tả contract. Migration dữ liệu không tạo cơ chế enforce role. Tài liệu này không xác minh lại trạng thái runtime hiện tại.

## 2. Operator — nhân viên hỗ trợ vận hành và tra cứu thanh toán

**Vai trò**: nhân viên hỗ trợ dịch vụ tài khoản/thanh toán, dùng SQLGuard sau khi yêu cầu đã đi qua quy trình xác thực riêng. Có thể tìm hồ sơ, xác định OWNER/DISPONENT, giải thích giao dịch đã ghi nhận, xem thông tin lệnh thanh toán và thẻ ở mức metadata.

**Một ca xử lý:** khách hàng hỏi một khoản thanh toán → nhận account_id qua quy trình đã xác thực → xem giao dịch, lệnh và mã mục đích → trả bảng thông tin, giải thích phần có bằng chứng → chuyển bộ phận phù hợp nếu cần sửa lệnh, hoàn tiền hoặc kiểm tra khoản vay. Input là tài khoản/khoảng ngày và yêu cầu đã xác thực; output là thông tin tra cứu, không phải lệnh chuyển tiền mới.

### Bảng 1 — Đối chiếu nghiệp vụ operator

| Đề xuất/chức năng | Tương đương ngoài đời trong mô hình giả định | Đánh giá | Financial hỗ trợ và giới hạn |
|---|---|---|---|
| Vận hành thông thường | Hỗ trợ dịch vụ tài khoản | Hợp lý nếu giới hạn tra cứu | Không có quyền thực hiện giao dịch hoặc sửa hồ sơ |
| Tra cứu giao dịch | Giải đáp biến động tài khoản | Phù hợp | Đọc trans; balance là số dư sau giao dịch lịch sử, không cam kết số dư hiện tại |
| Lệnh chuyển tiền và mục đích | Tra cứu lệnh thanh toán định kỳ | Phù hợp có giới hạn | order/k_symbol/note; lệnh không chứng minh đã chuyển tiền thành công |
| Tra cứu khách hàng | Tìm hồ sơ phục vụ yêu cầu dịch vụ | Phù hợp | client_id/full_name/address; tên và địa chỉ không thay thế xác thực |
| Quan hệ tài khoản và thẻ | Xác định chủ tài khoản/người được quyền sử dụng và thẻ liên quan | Phù hợp | Đi qua disp; card_id/type/issued đủ tra cứu metadata, không cần placeholder |
| Không xem id_number, birth_date | Phân tách tra cứu với xác minh danh tính | Hợp lý cho role thu hẹp | Không thể mô tả role này là giao dịch viên làm KYC đầy đủ |
| Xem địa chỉ khách hàng | Hỗ trợ thông tin liên hệ/dịch vụ | Có lý do nhưng cần mục đích cụ thể | Policy đang cho phép; không có cập nhật địa chỉ hay chứng cứ giao nhận trong DB |
| Không đọc loan | Chuyển câu hỏi tín dụng sang bộ phận chuyên trách | Hợp lý theo scope D2 | Là quyết định phân công, không phải mọi nhân viên vận hành ngoài đời đều bị cấm loan |
| Trong phạm vi được giao | Chỉ xử lý hồ sơ/chi nhánh được phân công | Hợp lý nhưng chưa đáp ứng | Chưa có mapping nhân viên–tài khoản và chưa chứng minh lọc dòng |
| Admin toàn quyền | DBA/quản trị hệ thống | Không phù hợp với role này | Không được dùng tên “admin” để bỏ qua allowlist |

### Bảng 2 — Ma trận bảng/cột operator

| Bảng       | Cột            | Ý nghĩa                                             | Quyền   | Lý do / cách dùng                                                          |
| ---------- | -------------- | --------------------------------------------------- | ------- | -------------------------------------------------------------------------- |
| `client`   | `client_id`    | Mã hồ sơ khách hàng                                 | Đọc     | Tra cứu hồ sơ phục vụ dịch vụ                                              |
| `client`   | `gender`       | Giới tính                                           | **Cấm** | Thông tin cá nhân ngoài allowlist của role                                 |
| `client`   | `birth_date`   | Ngày sinh                                           | **Cấm** | Thông tin cá nhân ngoài allowlist của role                                 |
| `client`   | `district_id`  | Khu vực gắn khách hàng                              | Đọc     | Tra cứu hồ sơ phục vụ dịch vụ                                              |
| `client`   | `id_number`    | Mã định danh synthetic                              | **Cấm** | Cấm cả ba role theo quyết định D2; không masking                           |
| `client`   | `full_name`    | Họ tên synthetic                                    | Đọc     | Tra cứu hồ sơ phục vụ dịch vụ                                              |
| `client`   | `address`      | Địa chỉ synthetic                                   | Đọc     | Tra cứu hồ sơ phục vụ dịch vụ                                              |
| `disp`     | `disp_id`      | Mã quan hệ khách hàng–tài khoản                     | Đọc     | Xác định khách hàng, tài khoản và quyền OWNER/DISPONENT                    |
| `disp`     | `client_id`    | Khách hàng trong quan hệ                            | Đọc     | Xác định khách hàng, tài khoản và quyền OWNER/DISPONENT                    |
| `disp`     | `account_id`   | Tài khoản trong quan hệ                             | Đọc     | Xác định khách hàng, tài khoản và quyền OWNER/DISPONENT                    |
| `disp`     | `type`         | OWNER hoặc DISPONENT                                | Đọc     | Xác định khách hàng, tài khoản và quyền OWNER/DISPONENT                    |
| `account`  | `account_id`   | Mã tài khoản                                        | Đọc     | Tra cứu thông tin dịch vụ tài khoản                                        |
| `account`  | `district_id`  | Khu vực gắn tài khoản/chi nhánh                     | Đọc     | Tra cứu thông tin dịch vụ tài khoản                                        |
| `account`  | `frequency`    | Tần suất sao kê                                     | Đọc     | Tra cứu thông tin dịch vụ tài khoản                                        |
| `account`  | `date`         | Ngày mở tài khoản                                   | Đọc     | Tra cứu thông tin dịch vụ tài khoản                                        |
| `account`  | `service_note` | Ghi chú dịch vụ synthetic                           | Đọc     | Tra cứu thông tin dịch vụ tài khoản; text không có quyền ra lệnh cho Agent |
| `trans`    | `trans_id`     | Mã giao dịch                                        | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `account_id`   | Tài khoản phát sinh                                 | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `date`         | Ngày giao dịch                                      | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `type`         | Loại thu/chi theo mã nguồn                          | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `operation`    | Phương thức giao dịch                               | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `amount`       | Số tiền giao dịch                                   | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `balance`      | Số dư sau giao dịch                                 | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `k_symbol`     | Mã mục đích giao dịch                               | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `bank`         | Ngân hàng đối tác                                   | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `trans`    | `account`      | Tài khoản đối tác                                   | Đọc     | Giải thích giao dịch đã ghi nhận                                           |
| `order`    | `order_id`     | Mã lệnh thanh toán định kỳ                          | Đọc     | Tra cứu lệnh và mục đích thanh toán                                        |
| `order`    | `account_id`   | Tài khoản nguồn                                     | Đọc     | Tra cứu lệnh và mục đích thanh toán                                        |
| `order`    | `bank_to`      | Ngân hàng nhận                                      | Đọc     | Tra cứu lệnh và mục đích thanh toán                                        |
| `order`    | `account_to`   | Tài khoản nhận                                      | Đọc     | Tra cứu lệnh và mục đích thanh toán                                        |
| `order`    | `amount`       | Số tiền của lệnh                                    | Đọc     | Tra cứu lệnh và mục đích thanh toán                                        |
| `order`    | `k_symbol`     | Mã mục đích thanh toán                              | Đọc     | Tra cứu lệnh và mục đích thanh toán                                        |
| `order`    | `note`         | Ghi chú thanh toán synthetic                        | Đọc     | Tra cứu lệnh và mục đích thanh toán; text không có quyền ra lệnh cho Agent |
| `card`     | `card_id`      | Mã row thẻ nội bộ                                   | Đọc     | Tra cứu metadata thẻ                                                       |
| `card`     | `disp_id`      | Quan hệ khách hàng–tài khoản gắn thẻ                | Đọc     | Tra cứu metadata thẻ                                                       |
| `card`     | `type`         | Loại thẻ                                            | Đọc     | Tra cứu metadata thẻ                                                       |
| `card`     | `issued`       | Ngày phát hành                                      | Đọc     | Tra cứu metadata thẻ                                                       |
| `card`     | `placeholder`  | Token synthetic; không phải số thẻ/CVV/PIN thật     | **Cấm** | Cấm cả ba role theo quyết định D2; không masking                           |
| `loan`     | **Toàn bảng**  | Mọi cột                                             | **Cấm** | Ngoài phạm vi role; dành cho theo dõi tín dụng                             |
| `district` | `district_id`  | Mã khu vực                                          | Đọc     | Tên và vùng để diễn giải hồ sơ                                             |
| `district` | `A2`           | Tên khu vực                                         | Đọc     | Tên và vùng để diễn giải hồ sơ                                             |
| `district` | `A3`           | Vùng                                                | Đọc     | Tên và vùng để diễn giải hồ sơ                                             |
| `district` | `A4`           | Dân số                                              | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A5`           | Số đơn vị dân cư dưới 499 người theo mô tả nguồn    | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A6`           | Số đơn vị dân cư 500–1.999 người                    | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A7`           | Số đơn vị dân cư 2.000–9.999 người                  | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A8`           | Số đơn vị dân cư trên 10.000 người theo mô tả nguồn | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A9`           | Chưa có diễn giải đủ tin cậy trong dictionary local | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A10`          | Tỷ lệ dân số đô thị                                 | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A11`          | Lương trung bình khu vực                            | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A12`          | Tỷ lệ thất nghiệp 1995                              | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A13`          | Tỷ lệ thất nghiệp 1996                              | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A14`          | Số doanh nhân trên 1.000 dân                        | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A15`          | Số vụ phạm tội 1995                                 | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |
| `district` | `A16`          | Số vụ phạm tội 1996                                 | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân          |

## 3. Analyst — chuyên viên BI về khách hàng, tài khoản và giao dịch

**Vai trò**: chuyên viên báo cáo hoạt động ngân hàng bán lẻ, trả lời câu hỏi về quy mô khách hàng, tài khoản mở theo kỳ, cơ cấu hoạt động và dòng giao dịch theo vùng/thời gian.

**Một ca xử lý:** trưởng bộ phận hỏi hoạt động giao dịch theo vùng năm 1998 → analyst chốt vùng chi nhánh hay vùng khách hàng và đơn vị đếm → tổng hợp trans/account/district → trả bảng vùng, số giao dịch, số tài khoản hoạt động, tổng amount → giải thích giới hạn dữ liệu.

### Bảng 1 — Đối chiếu nghiệp vụ analyst

| Đề xuất/chức năng | Tương đương ngoài đời trong mô hình giả định | Đánh giá | Financial hỗ trợ và giới hạn |
|---|---|---|---|
| Tổng hợp khách hàng | Báo cáo cơ cấu khách hàng theo vùng/giới tính | Phù hợp | COUNT DISTINCT client_id; không có tuổi vì birth_date bị cấm |
| Tổng hợp tài khoản | Báo cáo mở tài khoản, tần suất sao kê | Phù hợp | account.date/frequency; chưa có trạng thái đóng tài khoản nên không tự tính churn |
| Tổng hợp giao dịch | Theo dõi khối lượng và giá trị giao dịch | Phù hợp | trans date/type/operation/amount; chuẩn hóa mã thu/chi trước tính dòng ròng |
| Phân tích kinh tế vùng | Bổ sung bối cảnh cho báo cáo vùng | Phù hợp có giới hạn | A4/A10–A13; A11 là lương vùng, không phải thu nhập khách hàng |
| Chỉ trả tổng hợp | Kênh báo cáo hạn chế nhận diện cá thể | Hợp lý cho SQLGuard | Allowlist chưa đủ: cần kiểm grouping/filter/output; SUM một khách hàng vẫn có thể lộ dữ liệu |
| Không đọc tên/địa chỉ/notes | Tách báo cáo khỏi hồ sơ dịch vụ cá nhân | Phù hợp mục đích hiện tại | client_id dùng nội bộ JOIN/COUNT, không phải dữ liệu vô hại để xuất tùy ý |
| Cấm loan/card/order | BI chỉ tập trung khách hàng–tài khoản–giao dịch | Hợp lý khi mô tả scope rõ | Không đại diện toàn bộ BI ngân hàng, không làm dashboard khoản vay/thẻ/lệnh |
| Dùng SQL tổng hợp để trả danh sách cá thể | Truy vấn tra cứu được ngụy trang thành báo cáo | Không hợp lệ | GROUP BY account_id hoặc nhóm quá nhỏ không tự trở thành an toàn |
### Bảng 2 — Ma trận bảng/cột analyst

| Bảng       | Cột            | Ý nghĩa                                             | Quyền      | Lý do / cách dùng                                                 |
| ---------- | -------------- | --------------------------------------------------- | ---------- | ----------------------------------------------------------------- |
| `client`   | `client_id`    | Mã hồ sơ khách hàng                                 | TH–khóa    | JOIN/COUNT nội bộ; không xuất ID cá thể                           |
| `client`   | `gender`       | Giới tính                                           | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `client`   | `birth_date`   | Ngày sinh                                           | **Cấm**    | Thông tin cá nhân ngoài allowlist của role                        |
| `client`   | `district_id`  | Khu vực gắn khách hàng                              | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `client`   | `id_number`    | Mã định danh synthetic                              | **Cấm**    | Cấm cả ba role theo quyết định D2; không masking                  |
| `client`   | `full_name`    | Họ tên synthetic                                    | **Cấm**    | Thông tin cá nhân ngoài allowlist của role                        |
| `client`   | `address`      | Địa chỉ synthetic                                   | **Cấm**    | Thông tin cá nhân ngoài allowlist của role                        |
| `disp`     | `disp_id`      | Mã quan hệ khách hàng–tài khoản                     | **Cấm**    | Không được cấp trong policy hiện hành                             |
| `disp`     | `client_id`    | Khách hàng trong quan hệ                            | TH–khóa    | JOIN/COUNT nội bộ; không xuất ID cá thể                           |
| `disp`     | `account_id`   | Tài khoản trong quan hệ                             | TH–khóa    | JOIN/COUNT nội bộ; không xuất ID cá thể                           |
| `disp`     | `type`         | OWNER hoặc DISPONENT                                | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `account`  | `account_id`   | Mã tài khoản                                        | TH–khóa    | JOIN/COUNT nội bộ; không xuất ID cá thể                           |
| `account`  | `district_id`  | Khu vực gắn tài khoản/chi nhánh                     | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `account`  | `frequency`    | Tần suất sao kê                                     | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `account`  | `date`         | Ngày mở tài khoản                                   | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `account`  | `service_note` | Ghi chú dịch vụ synthetic                           | **Cấm**    | Text dịch vụ ngoài phạm vi được cấp                               |
| `trans`    | `trans_id`     | Mã giao dịch                                        | TH–khóa    | JOIN/COUNT nội bộ; không xuất ID cá thể                           |
| `trans`    | `account_id`   | Tài khoản phát sinh                                 | TH–khóa    | JOIN/COUNT nội bộ; không xuất ID cá thể                           |
| `trans`    | `date`         | Ngày giao dịch                                      | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `trans`    | `type`         | Loại thu/chi theo mã nguồn                          | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `trans`    | `operation`    | Phương thức giao dịch                               | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `trans`    | `amount`       | Số tiền giao dịch                                   | TH–số liệu | Chỉ tiêu tổng hợp/bối cảnh vùng; không xuất giao dịch cá thể      |
| `trans`    | `balance`      | Số dư sau giao dịch                                 | **Cấm**    | Không được cấp trong policy hiện hành                             |
| `trans`    | `k_symbol`     | Mã mục đích giao dịch                               | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `trans`    | `bank`         | Ngân hàng đối tác                                   | **Cấm**    | Thông tin đối tác thanh toán ngoài phạm vi được cấp               |
| `trans`    | `account`      | Tài khoản đối tác                                   | **Cấm**    | Thông tin đối tác thanh toán ngoài phạm vi được cấp               |
| `order`    | **Toàn bảng**  | Mọi cột                                             | **Cấm**    | Ngoài scope báo cáo giao dịch đã ghi nhận                         |
| `card`     | **Toàn bảng**  | Mọi cột                                             | **Cấm**    | Ngoài phạm vi role; không cần dữ liệu thẻ                         |
| `loan`     | **Toàn bảng**  | Mọi cột                                             | **Cấm**    | Ngoài phạm vi role; dành cho theo dõi tín dụng                    |
| `district` | `district_id`  | Mã khu vực                                          | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `district` | `A2`           | Tên khu vực                                         | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `district` | `A3`           | Vùng                                                | TH–chiều   | Nhóm/lọc/nhãn báo cáo tổng hợp; không trả row cá thể              |
| `district` | `A4`           | Dân số                                              | TH–chiều   | Chỉ số của cả vùng, dùng làm bối cảnh/lọc vùng (24/10, chờ nhóm duyệt)      |
| `district` | `A5`           | Số đơn vị dân cư dưới 499 người theo mô tả nguồn    | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A6`           | Số đơn vị dân cư 500–1.999 người                    | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A7`           | Số đơn vị dân cư 2.000–9.999 người                  | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A8`           | Số đơn vị dân cư trên 10.000 người theo mô tả nguồn | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A9`           | Chưa có diễn giải đủ tin cậy trong dictionary local | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A10`          | Tỷ lệ dân số đô thị                                 | TH–chiều   | Chỉ số của cả vùng, dùng làm bối cảnh/lọc vùng (24/10, chờ nhóm duyệt)      |
| `district` | `A11`          | Lương trung bình khu vực                            | TH–chiều   | Chỉ số của cả vùng, dùng làm bối cảnh/lọc vùng (24/10, chờ nhóm duyệt)      |
| `district` | `A12`          | Tỷ lệ thất nghiệp 1995                              | TH–chiều   | Chỉ số của cả vùng, dùng làm bối cảnh/lọc vùng (24/10, chờ nhóm duyệt)      |
| `district` | `A13`          | Tỷ lệ thất nghiệp 1996                              | TH–chiều   | Chỉ số của cả vùng, dùng làm bối cảnh/lọc vùng (24/10, chờ nhóm duyệt)      |
| `district` | `A14`          | Số doanh nhân trên 1.000 dân                        | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A15`          | Số vụ phạm tội 1995                                 | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A16`          | Số vụ phạm tội 1996                                 | **Cấm**    | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
## 4. Credit officer — chuyên viên theo dõi khoản vay sau giải ngân

**Vai trò**: chuyên viên theo dõi danh mục khoản vay và hỗ trợ kiểm tra thanh toán. Được nhận diện tên chủ tài khoản, xem hợp đồng vay và giao dịch liên quan, lập danh sách khoản vay cần theo dõi.

**Một ca xử lý:** cần rà soát khoản vay status D → lấy loan, nối account–disp–client và xác định OWNER → xem giao dịch UVER trong kỳ và mức payments của hợp đồng → trả danh sách khoản vay, tên chủ, amount ban đầu, thời hạn và các giao dịch liên quan → đánh dấu cần xác minh ở hệ thống quản lý khoản vay.

### Bảng 1 — Đối chiếu nghiệp vụ credit_officer

| Đề xuất/chức năng | Tương đương ngoài đời trong mô hình giả định | Đánh giá | Financial hỗ trợ và giới hạn |
|---|---|---|---|
| Theo dõi dư nợ | Theo dõi số tiền còn phải trả theo hợp đồng | Hợp lý về mục tiêu nhưng dữ liệu chưa đủ | loan.amount là vốn vay ban đầu; thiếu sổ phân bổ gốc/lãi, lịch trả và dư nợ hiện hành |
| Khoản vay có vấn đề | Lập danh sách khoản vay cần kiểm tra | Phù hợp ở mức status nguồn | B/D phản ánh trạng thái theo dataset; không đồng nhất nhóm nợ pháp lý hiện hành |
| Thời hạn trả | Theo dõi kỳ hạn và ngày kết thúc dự kiến | Hỗ trợ một phần | date + duration tính dự kiến; chưa có lịch từng kỳ, gia hạn/ngày thực trả |
| Đối chiếu giao dịch | Kiểm tra giao dịch có mục đích vay trên tài khoản liên quan | Phù hợp nếu thu hẹp scope | trans.k_symbol/amount/date; cần quy tắc phân bổ để xác nhận nghĩa vụ đã thanh toán |
| Đối chiếu order với payments | Tìm lệnh định kỳ có giá trị cần rà soát | Phù hợp cho kiểm tra sơ bộ | order không phải bằng chứng tiền đã trả; không kết luận tất toán |
| Đọc full_name | Nhận diện hồ sơ cần theo dõi | Phù hợp và đã được chốt | Nối qua disp; phân biệt OWNER với DISPONENT; tên không thay định danh xác thực |
| Cấm id_number/address | Tách theo dõi danh mục khỏi KYC/liên hệ thu hồi | Hợp lý cho phạm vi hẹp | Không đủ để tự làm hồ sơ vay mới hay quy trình liên hệ khách hàng đầy đủ |
| Kiểm tra dữ liệu | Kiểm tính nhất quán của tập dữ liệu khoản vay | Phù hợp nếu giới hạn | Không phải quyền kiểm toán độc lập toàn ngân hàng, không được đọc mọi bảng |
| Thẩm định/phê duyệt vay | Đánh giá khả năng trả nợ và quyết định tín dụng | Ngoài phạm vi | Thiếu thu nhập cá nhân, lịch sử tín dụng, tài sản bảo đảm; SQLGuard chỉ đọc |
| Phân tích rủi ro vùng | Báo cáo danh mục theo vùng, tham chiếu chỉ số vùng | Hợp lý có giới hạn | A11/A12/A13 không thay dữ liệu tài chính cá nhân hoặc mô hình chấm điểm |

### Bảng 2 — Ma trận bảng/cột credit_officer

| Bảng | Cột | Ý nghĩa | Quyền | Lý do / cách dùng |
|---|---|---|---|---|
| `client` | `client_id` | Mã hồ sơ khách hàng | Đọc | Nhận diện hồ sơ theo dõi khoản vay |
| `client` | `gender` | Giới tính | **Cấm** | Thông tin cá nhân ngoài allowlist của role |
| `client` | `birth_date` | Ngày sinh | **Cấm** | Thông tin cá nhân ngoài allowlist của role |
| `client` | `district_id` | Khu vực gắn khách hàng | Đọc | Nhận diện hồ sơ theo dõi khoản vay |
| `client` | `id_number` | Mã định danh synthetic | **Cấm** | Cấm cả ba role theo quyết định D2; không masking |
| `client` | `full_name` | Họ tên synthetic | Đọc | Nhận diện hồ sơ theo dõi khoản vay |
| `client` | `address` | Địa chỉ synthetic | **Cấm** | Thông tin cá nhân ngoài allowlist của role |
| `disp` | `disp_id` | Mã quan hệ khách hàng–tài khoản | Đọc | Nối khoản vay đến khách hàng và xác định OWNER |
| `disp` | `client_id` | Khách hàng trong quan hệ | Đọc | Nối khoản vay đến khách hàng và xác định OWNER |
| `disp` | `account_id` | Tài khoản trong quan hệ | Đọc | Nối khoản vay đến khách hàng và xác định OWNER |
| `disp` | `type` | OWNER hoặc DISPONENT | Đọc | Nối khoản vay đến khách hàng và xác định OWNER |
| `account` | `account_id` | Mã tài khoản | Đọc | Ngữ cảnh tài khoản gắn khoản vay |
| `account` | `district_id` | Khu vực gắn tài khoản/chi nhánh | Đọc | Ngữ cảnh tài khoản gắn khoản vay |
| `account` | `frequency` | Tần suất sao kê | Đọc | Ngữ cảnh tài khoản gắn khoản vay |
| `account` | `date` | Ngày mở tài khoản | Đọc | Ngữ cảnh tài khoản gắn khoản vay |
| `account` | `service_note` | Ghi chú dịch vụ synthetic | **Cấm** | Text dịch vụ ngoài phạm vi được cấp |
| `trans` | `trans_id` | Mã giao dịch | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `account_id` | Tài khoản phát sinh | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `date` | Ngày giao dịch | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `type` | Loại thu/chi theo mã nguồn | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `operation` | Phương thức giao dịch | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `amount` | Số tiền giao dịch | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `balance` | Số dư sau giao dịch | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `k_symbol` | Mã mục đích giao dịch | Đọc | Kiểm tra giao dịch liên quan khoản vay |
| `trans` | `bank` | Ngân hàng đối tác | **Cấm** | Thông tin đối tác thanh toán ngoài phạm vi được cấp |
| `trans` | `account` | Tài khoản đối tác | **Cấm** | Thông tin đối tác thanh toán ngoài phạm vi được cấp |
| `order` | `order_id` | Mã lệnh thanh toán định kỳ | Đọc | Đối chiếu lệnh với nghĩa vụ định kỳ ở mức sơ bộ |
| `order` | `account_id` | Tài khoản nguồn | Đọc | Đối chiếu lệnh với nghĩa vụ định kỳ ở mức sơ bộ |
| `order` | `bank_to` | Ngân hàng nhận | **Cấm** | Thông tin đối tác thanh toán ngoài phạm vi được cấp |
| `order` | `account_to` | Tài khoản nhận | **Cấm** | Thông tin đối tác thanh toán ngoài phạm vi được cấp |
| `order` | `amount` | Số tiền của lệnh | Đọc | Đối chiếu lệnh với nghĩa vụ định kỳ ở mức sơ bộ |
| `order` | `k_symbol` | Mã mục đích thanh toán | Đọc | Đối chiếu lệnh với nghĩa vụ định kỳ ở mức sơ bộ |
| `order` | `note` | Ghi chú thanh toán synthetic | **Cấm** | Text dịch vụ ngoài phạm vi được cấp |
| `card` | **Toàn bảng** | Mọi cột | **Cấm** | Ngoài phạm vi role; không cần dữ liệu thẻ |
| `loan` | `loan_id` | Mã khoản vay | Đọc | Theo dõi hợp đồng và trạng thái khoản vay |
| `loan` | `account_id` | Tài khoản gắn khoản vay | Đọc | Theo dõi hợp đồng và trạng thái khoản vay |
| `loan` | `date` | Ngày khoản vay theo nguồn | Đọc | Theo dõi hợp đồng và trạng thái khoản vay |
| `loan` | `amount` | Số tiền vay ban đầu | Đọc | Theo dõi hợp đồng và trạng thái khoản vay |
| `loan` | `duration` | Thời hạn vay, tháng | Đọc | Theo dõi hợp đồng và trạng thái khoản vay |
| `loan` | `payments` | Số tiền thanh toán hằng tháng | Đọc | Theo dõi hợp đồng và trạng thái khoản vay |
| `loan` | `status` | Trạng thái khoản vay theo mã nguồn | Đọc | Theo dõi hợp đồng và trạng thái khoản vay |
| `district` | `district_id` | Mã khu vực | Đọc | Bối cảnh vùng của danh mục |
| `district` | `A2` | Tên khu vực | Đọc | Bối cảnh vùng của danh mục |
| `district` | `A3` | Vùng | Đọc | Bối cảnh vùng của danh mục |
| `district` | `A4` | Dân số | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A5` | Số đơn vị dân cư dưới 499 người theo mô tả nguồn | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A6` | Số đơn vị dân cư 500–1.999 người | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A7` | Số đơn vị dân cư 2.000–9.999 người | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A8` | Số đơn vị dân cư trên 10.000 người theo mô tả nguồn | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A9` | Chưa có diễn giải đủ tin cậy trong dictionary local | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A10` | Tỷ lệ dân số đô thị | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A11` | Lương trung bình khu vực | Đọc | Bối cảnh vùng của danh mục |
| `district` | `A12` | Tỷ lệ thất nghiệp 1995 | Đọc | Bối cảnh vùng của danh mục |
| `district` | `A13` | Tỷ lệ thất nghiệp 1996 | Đọc | Bối cảnh vùng của danh mục |
| `district` | `A14` | Số doanh nhân trên 1.000 dân | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A15` | Số vụ phạm tội 1995 | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
| `district` | `A16` | Số vụ phạm tội 1996 | **Cấm** | Chỉ số vùng ngoài allowlist hiện hành; không hàm ý bí mật tự thân |
## 5. Database bổ sung

| Table   | Bổ sung                           |
| ------- | --------------------------------- |
| client  | id_number<br>full_name<br>address |
| card    | placeholder                       |
| account | service_note                      |
| order   | note                              |
