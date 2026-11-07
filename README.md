# Quản lý công việc 2FA (online)

Ứng dụng web theo dõi số lượng công việc, trạng thái hoàn thành và tổng tiền. Mỗi user chỉ đọc/sửa/xuất dữ liệu của chính mình. Admin tạo/khóa tài khoản; admin không xem nội dung danh sách riêng của user.

## Phạm vi an toàn
Đây là công cụ quản lý và tính tiền, **không tự động thay đổi 2FA**. Không nhập/lưu mật khẩu tài khoản bên ngoài, mã OTP, seed/secret 2FA, cookie hay recovery code. Chỉ dùng mã đơn hoặc nhãn không nhạy cảm.

## Chạy thử trên máy
Yêu cầu Node.js 20+.

```bash
npm install
# Linux/macOS:
ADMIN_USERNAME=admin ADMIN_PASSWORD='DoiMatKhauThatDai!' SESSION_SECRET='chuoi-bi-mat-ngau-nhien-dai' npm start
# Windows PowerShell:
$env:ADMIN_USERNAME='admin'
$env:ADMIN_PASSWORD='DoiMatKhauThatDai!'
$env:SESSION_SECRET='chuoi-bi-mat-ngau-nhien-dai'
npm start
```

Mở http://localhost:3000. Đăng nhập bằng tài khoản admin đã đặt ở trên. Từ dashboard, vào Quản lý tài khoản để tạo user.

## Đưa lên mạng
Có thể deploy lên dịch vụ Node.js hỗ trợ persistent disk (ví dụ Render):
1. Tạo repository Git và đẩy toàn bộ project lên.
2. Tạo Web Service từ repository; Build command: `npm install`; Start command: `npm start`.
3. Thêm biến môi trường `ADMIN_USERNAME`, `ADMIN_PASSWORD` (mật khẩu mạnh), `SESSION_SECRET` (chuỗi ngẫu nhiên dài), `NODE_ENV=production`, `DATA_DIR=/var/data`, `DB_FILE=/var/data/data.sqlite`.
4. Gắn persistent disk vào `/var/data` để dữ liệu SQLite và session không mất khi deploy/restart.
5. Bật HTTPS; không dùng secret mặc định trong production.

Lưu ý: bản mẫu này phù hợp MVP một máy chủ. Nếu cần nhiều máy chủ/scale-out, nên chuyển sang PostgreSQL và session store dùng chung.

## Tính tiền
Tổng tiền trên dashboard = tổng đơn giá của các mục đã đánh dấu “Đã hoàn thành”. Đơn giá nhập theo từng mục (có thể khác nhau).
