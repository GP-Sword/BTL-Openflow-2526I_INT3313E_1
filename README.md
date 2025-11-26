# Báo cáo BTL Openflow: Hệ thống Router SDN Hoàn Chỉnh

## 1. Giới thiệu

Báo cáo này trình bày thiết kế và cài đặt một hệ thống SDN Router sử dụng POX controller và Mininet. Hệ thống đáp ứng đầy đủ các yêu cầu: chuyển mạch L2, định tuyến L3 giữa 3 subnet, xử lý ARP, Firewall L4, cài đặt Flow để tối ưu hiệu năng và giám sát lưu lượng mạng. Đặc biệt, hệ thống xử lý topo mạng có vòng lặp (loop) thông qua Spanning Tree Protocol.

## 2. Kiến trúc Hệ thống

### 2.1. Topology

Hệ thống mạng được xây dựng trên Mininet với cấu trúc hình tam giác (Ring Topology):

- **3 Switches (s1, s2, s3):** Kết nối vòng tròn (s1-s2, s2-s3, s3-s1).

- **3 Subnet:**

  + Subnet A (10.0.1.0/24) -> s1 (Gateway 10.0.1.1)

  + Subnet B (10.0.2.0/24) -> s2 (Gateway 10.0.2.1)

  + Subnet C (10.0.3.0/24) -> s3 (Gateway 10.0.3.1)

- **Hosts:** Mỗi subnet có 2 host giả lập.

- **Controller:** POX Controller chạy tập trung. Do topo có vòng lặp vật lý, module **Spanning Tree Protocol (STP)** được kích hoạt để khóa logic một cổng, ngăn chặn Broadcast Storm.

### 2.2. Các Module Controller

Mã nguồn được tổ chức thành 6 file riêng biệt để dễ quản lý:

- `controller.py`: Chương trình chính, khởi tạo STP, Discovery và các module con.

- `arp_handler.py`: Xử lý toàn bộ logic liên quan đến ARP (ARP Proxy cho Gateway và ARP Client cho Host).

- `firewall.py`: Chứa bảng luật ACL và logic kiểm tra gói tin.

- `ip_handler.py`: "Bộ não" định tuyến, quyết định đường đi của gói tin IP.

- `flow_installer.py`: Chịu trách nhiệm đẩy rule xuống switch (Data Plane).

- `monitor.py`: Thu thập số liệu thống kê từ switch.

## 3. Chi tiết Logic Hoạt động

Phần này mô tả chi tiết cách code xử lý từng loại gói tin và các cơ chế bên trong.

### 3.1. Module Firewall (Tầng 4)

Firewall hoạt động ở chế độ **"Default Allow"** (Cho phép tất cả trừ khi bị chặn). Module này được gọi đầu tiên khi có gói tin IP đi vào.

**Cấu trúc ACL (Access Control List):** Code sử dụng một danh sách các tuples để định nghĩa luật:

```
# Format: (Giao thức, Port, Hành động)
self.rules = [
    ("TCP", 22, "DENY"),   # Rule 1: Chặn SSH (Port 22)
    ("TCP", 80, "DENY"),   # Rule 2: Chặn Web/HTTP (Port 80)
    ("UDP", 53, "ALLOW"),  # Rule 3: Cho phép DNS (Port 53)
]
```

**Logic xử lý** **(** `is_allowed` **function):**

1\. Parse header IP để lấy Protocol (TCP=6, UDP=17).

2\. Parse header Transport (TCP/UDP) để lấy `dst_port`.

3\. Duyệt qua danh sách `self.rules`:

- Nếu khớp Protocol VÀ khớp Port:

  - Nếu Action là "DENY" -> Trả về `False` (Drop gói ngay lập tức).

  - Nếu Action là "ALLOW" -> Trả về `True` (Cho phép đi tiếp).

4\. Nếu duyệt hết danh sách mà không khớp rule nào -> Trả về `True`.

### 3.2. Module ARP Handler

Module này giải quyết vấn đề ánh xạ địa chỉ IP <-> MAC:

- **Xử lý ARP Request tới Gateway**:

  - Khi Host gửi ARP Request hỏi `Who has 10.0.x.1?` (Gateway ảo).

  - Controller nhận gói tin, kiểm tra IP đích.

  - Tự tạo gói ARP Reply với `hw_src` là MAC ảo của Router (ví dụ: `00:00:00:00:01:01`) và gửi lại cho Host.

  - *Mục đích*: Giúp Host tin rằng Gateway là một thiết bị thực.

- **Cơ chế "ARP Hold-Down" (Hàng đợi):**

  - Khi Router cần chuyển gói tin IP tới Host đích nhưng chưa biết MAC đích.

  - Router **không drop gói tin** mà lưu vào hàng đợi `waiting_packets[dest_ip]`.

  - Router gửi ARP Request (Broadcast) hỏi `Who has [dest_ip]`?.

  - Khi nhận được ARP Reply từ Host đích -> Module kích hoạt hàm `process_waiting_packets` để lấy các gói tin trong hàng đợi ra và gửi đi.

### 3.3. Module IP Handler (Routing Logic)

Đây là logic cốt lõi mô phỏng hoạt động của Router L3:

1\. **Kiểm tra điểm đến**:

- Nếu IP đích là Gateway (ví dụ ping 10.0.1.1) -> Chuyển sang xử lý ICMP Reply (Ping).

- Nếu IP đích thuộc subnet khác -> Thực hiện định tuyến.

2\. **Quy trình Forwarding:**

- **B1: Lookup Route:** Xác định Gateway của subnet đích (trong bài lab này logic đơn giản hóa bằng cách check prefix IP).

- **B2: Resolve MAC:** Tra bảng ARP Cache để tìm MAC của Host đích.

- **B3: Rewrite Header** (Quan trọng): Để gói tin đi qua được router, header Ethernet phải được viết lại:

  - `eth.src` = MAC của Router (Interface đầu ra).

  - `eth.dst` = MAC của Host đích (Next Hop).

- **B4: Output:** Đẩy gói tin ra port nối với Host đích (dựa trên bảng L2 Learning mac_to_port).

### 3.4. Module Flow Installation (Tối ưu Data Plane)

Để tránh việc Controller phải xử lý từng gói tin (gây quá tải), sau khi gói tin đầu tiên được định tuyến thành công, module này sẽ cài đặt một "luật cứng" xuống Switch.

- **Nội dung Flow Mod:**

  - **Match:** Khớp chính xác IP đích (`nw_dst`), loại gói tin IP.

  - **Action:**

    - `set_dl_src`: Ghi đè MAC nguồn thành MAC Router.

    - `set_dl_dst`: Ghi đè MAC đích thành MAC Host nhận.

    - `output`: Đẩy ra port tương ứng.

  - **Timeout:** `idle_timeout=30s` (Tự xóa nếu không có lưu lượng).

- **Hiệu quả:** Các gói tin thứ 2, 3... sẽ được Switch xử lý trực tiếp ở tốc độ phần cứng (Wire speed) mà không cần gửi lên Controller (`PacketIn`).

### 3.5. Module Monitoring

- Sử dụng `Timer` lặp lại mỗi 5 giây.

- Gửi bản tin `ofp_stats_request` yêu cầu Switch báo cáo số liệu.

- Khi nhận `ofp_stats_reply`, code sẽ phân tích:

    - Cộng dồn `byte_count` của các flow có `nw_proto=6` vào biến đếm TCP.

    - Cộng dồn `byte_count` của các flow có `nw_proto=17` vào biến đếm UDP.

    - Thống kê lưu lượng theo từng địa chỉ IP nguồn (`nw_src`).

- Kết quả được in ra log console thời gian thực.
