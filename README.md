# LAB 01 - Mô phỏng Blockchain Layer 1

## 1. Giới thiệu

Đây là bài thực hành xây dựng một blockchain Layer 1 tối giản có khả năng
đạt đồng thuận và hoàn tất block trong môi trường mạng không ổn định.

Mục tiêu của hệ thống:

- Các node xác thực cùng hội tụ về một chuỗi block đã hoàn tất.
- Không có hai block khác nhau cùng height được hoàn tất.
- Giao dịch được xác thực chữ ký và thực thi trạng thái một cách xác định.
- Hệ thống vẫn đảm bảo an toàn khi thông điệp bị trễ, mất, trùng hoặc đảo thứ tự.
- Kết quả chạy lại cùng cấu hình và seed phải có log giống hệt nhau.

Mô hình giả định có `n = 3f + 1` validator và nhiều nhất `f` validator
Byzantine. Mạng có thể không ổn định trước thời điểm đồng bộ; sau đó thông
điệp giữa các node đúng được phân phối trong một khoảng thời gian giới hạn.

## 2. Cấu trúc dự án

```text
Lab01_Bloackchain_layer_1/
├── src/
│   ├── consensus/              # Cơ chế đồng thuận BFT
│   │   ├── engine.py           # Máy trạng thái consensus
│   │   └── locking.py          # Quy tắc locking/unlocking
│   ├── models/                 # Block, Vote, Transaction, Message
│   ├── crypto/                 # Chữ ký, hash, canonical encoding
│   ├── execution/              # State và thực thi giao dịch
│   ├── network/                # Mạng mô phỏng
│   ├── node.py                 # Node tích hợp các module
│   └── blockchain_simulator.py # Điểm chạy mô phỏng
├── tests/                      # Unit test và end-to-end test
├── scenarios/                  # Các kịch bản lỗi và Byzantine
├── config/                     # Cấu hình số node, seed, timeout
├── logs/                       # Log sinh ra khi chạy
├── scripts/                    # Script kiểm tra tính xác định
├── main.py                     # Entry point duy nhất
├── README.md
└── REPORT.pdf
```
