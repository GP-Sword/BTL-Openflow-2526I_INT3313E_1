# LAB CUỐI KỲ – XÂY DỰNG SDN GATEWAY HOÀN CHỈNH (ROUTER + FIREWALL + MONITORING)


## 1. Topology mạng

  Subnet A            Subnet B               Subnet C
 h1,h2 ---- s1 ---- s2 ---- h3,h4 ---- s3 ---- h5,h6
         \_______ liên kết giữa s1—s2—s3 ______/

s1, s2, s3 là OpenFlow switch đóng vai router

- Mỗi subnet bắt buộc có ít nhất 2 host

- Mỗi switch phải được gán IP gateway:

  - s1 → 10.0.1.1

  - s2 → 10.0.2.1

  - s3 → 10.0.3.1


## 2. Yêu cầu 1 – ARP Handler
Viết hàm xử lý ARP:

- Trả lời ARP request cho gateway của router

- Gửi ARP request khi MAC chưa có trong ARP cache

- Lưu ARP cache

- Tạo hàng đợi (queue) packet chờ ARP reply

## 3. Yêu cầu 2 – IP Packet Handler (Routing)

Sinh viên phải triển khai đầy đủ logic định tuyến giữa 3 subnet:

Khi nhận gói IPv4:

&nbsp;&nbsp;&nbsp; 1\. Parse Ethernet + IPv4 + ICMP/TCP

&nbsp;&nbsp;&nbsp; 2\. Kiểm tra routing table

&nbsp;&nbsp;&nbsp; 3\. Tính next-hop

&nbsp;&nbsp;&nbsp; 4\. Rewrite MAC (src = MAC router, dst = MAC next-hop)

&nbsp;&nbsp;&nbsp; 5\. Gửi packet_out qua đúng port

Sinh viên phải chứng minh router định tuyến được giữa tất cả 3 subnet.

## 4. Yêu cầu 3 – Flow Installation (Tối ưu hiệu năng)

Sau khi xử lý packet đầu tiên, phải cài đặt flow_mod lên switch:

- match: dl_type, nw_dst, nw_proto, …

- actions: set_dl_src, set_dl_dst, output

- reverse flow (chiều ngược lại) cũng phải được thiết lập


## 5. Yêu cầu 4 – Firewall tầng 4 (TCP/UDP)

Sinh viên phải xây dựng một ACL như ví dụ:
```
RULES = [
   ("INBOUND",  "TCP", 22, "DENY"),   # Chặn SSH vào subnet
   ("INBOUND",  "TCP", 80, "DENY"),   # Chặn HTTP
   ("OUTBOUND", "UDP", 53, "ALLOW"),  # Cho phép DNS
]
```

- So khớp giao thức: TCP (6), UDP (17)

- So khớp port: tp_dst

- So khớp chiều: in_port

- Flow DROP phải có priority cao

- Flow ALLOW có priority thấp hơn

 
## 6. Yêu cầu 5 – Monitoring (giám sát lưu lượng)

Sinh viên phải cài đặt module thu thập thống kê:

- Thống kê theo host: số byte gửi/nhận

- Thống kê theo giao thức: TCP/UDP/ICMP

- Sử dụng ofp_stats_request

- Cập nhật 5 giây/lần

## 7. Các tài liệu cần phải nộp

### 7.1. Mã nguồn controller

`arp_handler.py`
`ip_handler.py`
`firewall.py`
`flow_installer.py`
`monitor.py`
`controller.py`

### 7.2. File topo

`multi_router_topo.py`
