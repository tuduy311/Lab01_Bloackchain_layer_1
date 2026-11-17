# Cấu hình mô phỏng

Thư mục này chứa toàn bộ tham số chạy của simulator. Không có tham số nào bị
hard-code trong code: entry point `src/main.py` và checker
`src/deterministic_check.py` đều đọc file ở đây trước, sau đó mới áp dụng
tham số dòng lệnh (nếu có).

| File | Dùng cho |
| --- | --- |
| `simulation.json` | Cấu hình mặc định, dùng khi không truyền `--config` |
| `scenario_unstable_network.json` | Kịch bản mạng bất ổn định: drop/duplicate/delay trước thời điểm stabilize |

Chạy một file cấu hình:

```powershell
python -m src.main --config config/simulation.json
python -m src.main --config config/scenario_unstable_network.json
```

Định dạng là JSON, hoặc YAML nếu file có đuôi `.yaml`/`.yml`. Đường dẫn tương
đối bên trong file (ví dụ `logs/run.jsonl`) được tính từ thư mục gốc dự án, nên
chạy lệnh từ thư mục nào cũng cho cùng kết quả.

## Cấu trúc file

```json
{
  "run":        { "nodes": 8, "seed": 0, "height": 3, "log": "...", "summary": "..." },
  "simulation": { "gossip_interval": 0.25, "max_transactions": 100 },
  "network":    { "min_delay": 0.01, "max_delay": 0.05, "drop_rate": 0.0, ... },
  "timeout":    { "base": 1.0, "multiplier": 1.5, "max_timeout": 30.0, ... }
}
```

### `run`

| Khóa | Ý nghĩa |
| --- | --- |
| `nodes` | Số validator của run, đồng thời gán `SimulationConfig.num_nodes` |
| `seed` | Seed tái lập của mạng, key và proposer, đồng thời gán `SimulationConfig.seed` |
| `height` | Số block cần finalize trước khi dừng |
| `log` | Đường dẫn JSONL log sự kiện canonical |
| `summary` | Đường dẫn JSON summary (state root, counter, kết quả T8) |

### `simulation`

| Khóa | Ý nghĩa |
| --- | --- |
| `gossip_interval` | Chu kỳ gossip header/body của node (giây mô phỏng) |
| `max_transactions` | Số transaction tối đa proposer lấy vào một block |
| `initial_balances` | Số dư genesis; bỏ trống thì mỗi validator được cấp 1000 |
| `faulty_nodes` | Danh sách validator bị loại khỏi điều kiện target height |
| `silent_proposers` | Validator không gửi proposal (dùng cho kịch bản T6) |

### `network`

Các khóa trùng với `NetworkConfig` trong `src/network/network.py`:
`min_delay`, `max_delay`, `drop_rate`, `duplicate_rate`,
`pre_synchrony_max_delay`, `stabilize_at`, `enforce_header_gate`,
`rate_limit.{capacity,refill_per_second,inbound_capacity,inbound_window,peer_block_duration}`.
`num_nodes` và `seed` của mạng luôn lấy theo `run.nodes` và `run.seed`.

### `timeout`

Các khóa trùng với `TimeoutConfig` trong `src/consensus/timeout.py`:
`base`, `multiplier`, `max_timeout`, `jitter`, `seed`, `max_round`.

## Ghi đè bằng dòng lệnh

Tham số dòng lệnh có độ ưu tiên cao hơn file cấu hình:

```powershell
python -m src.main --config config/simulation.json --nodes 8 --seed 0 --height 3
```

Chỉ `nodes`, `seed`, `height`, `log`, `summary` ghi đè được từ dòng lệnh; các
tham số còn lại sửa trực tiếp trong file cấu hình.

