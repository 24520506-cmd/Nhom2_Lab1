# Threat Model cho `json_search()`

## 1. Bối cảnh và phạm vi

Hàm `json_search(key, data, role=...)` tìm giá trị theo tên trường trong JSON từ API giám sát hạ tầng mạng. Dữ liệu có thể gồm dict và list lồng nhau. Quyền đọc ba trường được định nghĩa trong `policy.py`.

Tài liệu này mô hình hóa các rủi ro cần kiểm soát khi triển khai hàm. `recursive_json_search.py` và `test_json_search.py` hiện là skeleton, chưa có phần hiện thực để kết luận lỗi đã tồn tại.

## 2. Actor và mục đích sử dụng

| Actor | Mục đích | Quyền theo `policy.py` |
|---|---|---|
| `admin` | Quản trị, kiểm tra cấu hình và xử lý sự cố | Đọc cả ba trường trong policy |
| `operator` | Vận hành và giám sát thiết bị | Đọc `managementIpAddress`, `issueSummary` |
| `viewer` | Xem thông tin sự cố | Chỉ đọc `issueSummary` trong ba trường |
| Người dùng chưa xác thực / role không hợp lệ | Không có quyền đọc được xác lập | Phải bị chặn bởi hệ thống; không được cấp quyền ngầm |

## 3. Asset và chính sách truy cập

| Asset | Vị trí trong dữ liệu mẫu | Role được phép | Lý do bảo vệ |
|---|---|---|---|
| `apiKey` | `enrichmentInfo.connectedDevice[].deviceDetails.apiKey` | `admin` | Chuỗi mẫu mang tính chất SNMP community, cần bảo mật |
| `managementIpAddress` | `enrichmentInfo.connectedDevice[].deviceDetails.managementIpAddress` | `admin`, `operator` | Địa chỉ quản trị thiết bị |
| `issueSummary` | `enrichmentInfo.issueDetails.issue[].issueSummary` | `admin`, `operator`, `viewer` | Thông tin sự cố cần kiểm soát theo policy |

Các trường như hostname, MAC, serial number và thông tin topology cũng xuất hiện trong dữ liệu nhưng chưa có quy tắc trong `policy.py`. Không suy diễn rằng tất cả những trường này là công khai. Ngoài ra, `issueSummary` có chứa IP thiết bị; quyền đọc summary không đồng nghĩa với việc ẩn toàn bộ thông tin IP khỏi viewer.

## 4. Luồng dữ liệu và trust boundary

1. Backend xác thực người dùng và xác định role.
2. Backend gọi `json_search()` với key yêu cầu, dữ liệu và role đáng tin cậy.
3. Hàm kiểm tra quyền theo `POLICY` trước khi trả kết quả.
4. Chỉ giá trị được phép mới đi ra phía người gọi.

Có hai ranh giới cần kiểm soát:

- **Client → backend:** client có thể điều khiển key yêu cầu nhưng không được tự quyết định role. Role phải lấy từ ngữ cảnh xác thực phía backend.
- **Hàm tìm kiếm → kết quả trả về:** dữ liệu nội bộ có thể chứa secret; kết quả ra ngoài phải qua kiểm tra quyền. Nếu hàm chỉ tìm key rồi trả giá trị, ranh giới phân quyền này bị bỏ qua.

`json_search()` nhận một chuỗi role không thể tự chứng minh danh tính người gọi. Xác thực và chống giả mạo role là trách nhiệm của tầng tích hợp.

## 5. Threat theo STRIDE

| ID | STRIDE | Kịch bản | Tác động | Kiểm soát / requirement |
|---|---|---|---|---|
| T-01 | Information Disclosure | `viewer` hoặc `operator` yêu cầu `apiKey`; hàm trả giá trị vì thiếu kiểm tra policy | Lộ chuỗi xác thực SNMP | SR-01, SR-02, SR-05 |
| T-02 | Information Disclosure / Elevation of Privilege | `viewer` đọc `managementIpAddress`, vượt quyền đọc được cấp | Lộ địa chỉ quản trị; vượt ranh giới phân quyền | SR-01, SR-03, SR-05 |
| T-03 | Spoofing / Elevation of Privilege | Viewer tự gửi `role="admin"` và backend tin giá trị này | Có quyền đọc dữ liệu chỉ dành cho admin | SR-08, kiểm soát tại backend |
| T-04 | Information Disclosure | Kiểm tra quyền ở lời gọi đầu nhưng bỏ quên role ở lời gọi đệ quy; hoặc trả nguyên object chứa trường bị hạn chế | Lộ dữ liệu qua cấu trúc lồng nhau | SR-06 |
| T-05 | Information Disclosure | Lỗi hoặc log ghi kèm giá trị secret khi từ chối truy cập | Secret vẫn bị lộ dù kết quả bị chặn | SR-07 |
| T-06 | Denial of Service | JSON quá sâu hoặc quá lớn làm cạn tài nguyên / vượt giới hạn đệ quy | Gián đoạn xử lý | Đề xuất giới hạn kích thước, độ sâu, thời gian ở triển khai thực tế |

Thay key từ `issueSummary` sang `apiKey` là một yêu cầu truy cập trái phép cần kiểm tra; riêng hành động đổi tham số không đủ để kết luận có threat Tampering. Tampering phù hợp hơn khi người dùng có thể sửa trái phép policy hoặc dữ liệu nội bộ.

## 6. Giả định và giới hạn

- `POLICY` và dữ liệu giám sát là tài nguyên do backend quản lý; người dùng không được sửa policy.
- Người dùng chỉ nhận kết quả qua hàm/API; nếu có quyền đọc trực tiếp toàn bộ JSON, kiểm soát trong hàm không bảo vệ được nguồn dữ liệu.
- Policy hiện phân quyền theo tên key, không theo thiết bị, tenant hoặc đường dẫn.
- Threat model không khẳng định hàm thực hiện xác thực, sửa dữ liệu hay truy cập mạng.
- Các kiểm soát JSON quá sâu/lớn là đề xuất triển khai; không phải yêu cầu hiện có trong `policy.py`.

## 7. Security property chính

Với các key được định nghĩa trong `POLICY`, giá trị chỉ được trả khi role hiện tại thuộc danh sách role được phép của key đó. Role không được phép phải nhận kết quả rỗng, kể cả khi trường nằm sâu trong dict/list.

Các security requirement và tiêu chí kiểm thử tương ứng nằm trong `SECURITY_REQUIREMENTS.md`.
