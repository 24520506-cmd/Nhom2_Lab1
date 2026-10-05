# Security Requirements cho `json_search()`

## 1. Phạm vi và căn cứ

Các yêu cầu SR-01 đến SR-07 cụ thể hóa phân quyền cho ba trường trong `policy.py` và hướng dẫn security test: gọi `json_search(key, data, role=...)` bằng role không được phép phải nhận kết quả rỗng.

Skeleton hiện chưa định nghĩa kiểu kết quả. Trong tài liệu này, chọn **list các giá trị tìm thấy**, với kết quả rỗng là **`[]`**, làm hợp đồng đề xuất để viết code và test nhất quán. Đây là quyết định thiết kế, không phải kiểu trả về đã có sẵn trong skeleton.

## 2. Security requirements

### SR-01 — Kiểm tra quyền trước khi trả dữ liệu

Với mỗi key có trong `POLICY`, hàm chỉ được trả giá trị khi `role in POLICY[key]`. Không được bỏ qua kiểm tra quyền vì giá trị đã được tìm thấy trong JSON.

**Tiêu chí kiểm thử:** chạy đầy đủ ma trận role × key ở mục 3.

### SR-02 — Bảo vệ `apiKey`

Chỉ `admin` được nhận giá trị `apiKey`. `operator` và `viewer` phải nhận `[]`.

**Tiêu chí kiểm thử:** admin nhận đúng giá trị mẫu; hai role còn lại nhận đúng `[]`.

### SR-03 — Bảo vệ `managementIpAddress`

Chỉ `admin` và `operator` được nhận giá trị `managementIpAddress`. `viewer` phải nhận `[]`.

**Tiêu chí kiểm thử:** hai role được phép nhận đúng IP mẫu; viewer nhận đúng `[]`.

### SR-04 — Cho phép đọc `issueSummary` theo policy

Cả `admin`, `operator` và `viewer` được nhận giá trị `issueSummary`.

**Tiêu chí kiểm thử:** mỗi role nhận đúng nội dung mẫu, tránh hiện thực từ chối mọi yêu cầu để làm security test pass.

### SR-05 — Từ chối truy cập không được phép

Khi role không thuộc danh sách được phép của một key trong policy, hàm phải trả `[]`, không trả một phần giá trị hay giá trị đã che nhưng vẫn chứa secret.

Role không xác định, role rỗng hoặc thiếu role không được tự động hưởng quyền admin để đọc các trường được bảo vệ.

**Tiêu chí kiểm thử:** role `guest`, chuỗi rỗng và trường hợp thiếu role không nhận dữ liệu của key được bảo vệ. Cách xử lý tham số thiếu cần được chốt cùng chữ ký hàm; không được mặc định thành admin.

### SR-06 — Không bypass phân quyền qua cấu trúc lồng nhau

Quyền truy cập phải giữ nguyên khi duyệt dict/list ở mọi độ sâu. Không được bỏ quên role trong lời gọi đệ quy. Không được trả nguyên object/container chứa giá trị bị hạn chế để né kiểm tra key con.

**Tiêu chí kiểm thử:** đặt `apiKey` ở nhiều độ sâu, trong list và tại nhiều vị trí; viewer/operator vẫn nhận `[]`. Nếu hỗ trợ trả container, thêm test chống lộ secret qua key cha.

### SR-07 — Không tiết lộ secret qua lỗi hoặc log

Việc từ chối truy cập không được đưa giá trị thật của trường bị bảo vệ vào kết quả, thông báo lỗi hoặc log.

**Tiêu chí kiểm thử:** lời gọi bị từ chối trả `[]`; nếu có log/thông báo lỗi, kiểm tra chúng không chứa giá trị secret từ fixture.

### SR-08 — Role lấy từ ngữ cảnh xác thực (tầng tích hợp)

Backend phải lấy role từ phiên hoặc ngữ cảnh người dùng đã được xác thực, không tin trực tiếp role do client gửi. Hàm nhận chuỗi `"admin"` không thể tự biết chuỗi đó có bị giả mạo hay không.

**Tiêu chí kiểm thử tích hợp:** viewer gửi role admin qua request vẫn bị xử lý với quyền viewer. Unit test chỉ truyền `role="admin"` vào hàm không chứng minh được yêu cầu này.

## 3. Ma trận kiểm thử tối thiểu

| Key | `admin` | `operator` | `viewer` |
|---|---|---|---|
| `apiKey` | Đúng giá trị | `[]` | `[]` |
| `managementIpAddress` | Đúng giá trị | Đúng giá trị | `[]` |
| `issueSummary` | Đúng giá trị | Đúng giá trị | Đúng giá trị |

Bổ sung test với role không hợp lệ, trường lồng sâu, key lặp ở nhiều vị trí và thông báo lỗi/log nếu có.

Khi kiểm tra trường hợp được phép, so sánh với giá trị kỳ vọng cụ thể từ fixture. Khi kiểm tra bị từ chối, so sánh chính xác với `[]`; không chỉ kiểm tra `result is not None`.

## 4. Mapping threat → requirement

| Threat | Requirement |
|---|---|
| T-01 — Lộ `apiKey` | SR-01, SR-02, SR-05 |
| T-02 — Viewer đọc IP quản trị | SR-01, SR-03, SR-05 |
| T-03 — Giả mạo role admin | SR-08 |
| T-04 — Bypass qua đệ quy/container | SR-06 |
| T-05 — Lộ secret qua lỗi/log | SR-07 |

SR-04 kiểm tra quyền truy cập hợp lệ để đảm bảo chức năng vẫn hoạt động đúng.

## 5. Điểm cần chốt khi thiết kế

`policy.py` chỉ quy định ba key, không nói rõ cách xử lý key ngoài policy. Không được mô tả default deny cho mọi key như một quy tắc đã có sẵn trong bài.

**Đề xuất bảo mật:** từ chối key ngoài policy bằng `[]` và bổ sung policy cho các key cần mở quyền. Nếu yêu cầu chức năng của bài cho phép tìm key khác, cần ghi rõ quy tắc và test tương ứng trước khi hiện thực.

Giới hạn kích thước/độ sâu JSON là kiểm soát đề xuất cho T-06 khi triển khai thực tế; cần xác định ngưỡng và hành vi lỗi cụ thể trước khi biến thành requirement bắt buộc.
