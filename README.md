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

## 2. Thành viên

| Thành viên | MSSV | Phụ trách |
| --- | --- | --- |
| TV1 - Tú | ... | Consensus |
| TV2 - Tuấn | ... | Models, Cryptography, Execution |
| TV3 - Phú | ... | Network, Scheduler, Proposer, Timeout |
| TV4 - Phong | ... | Integration and Testing |
| TV5 - Trí | ... | Logging, Monitoring, Replay |

## 3. Cấu trúc dự án

Thư mục gốc phải đặt tên theo cú pháp `Lab01_ID1_ID2_ID3_ID4_ID5` (ID1–ID5 là
MSSV của 5 thành viên) và được nén thành file `.zip` cùng tên. Bên trong chỉ có
sáu thành phần theo quy định của đề bài:

```text
Lab01_ID1_ID2_ID3_ID4_ID5/
├── src/
│   ├── consensus/
│   │   ├── engine.py           # Máy trạng thái consensus
│   │   ├── locking.py          # Quy tắc locking/unlocking
│   │   ├── proposer.py         # Chọn proposer theo (height, round)
│   │   └── timeout.py          # Round timeout
│   ├── crypto/                 # Chữ ký, hash, canonical encoding
│   ├── execution/              # State và thực thi giao dịch
│   ├── models/                 # Block, Vote, Transaction, Message
│   ├── network/                # Mạng mô phỏng
│   ├── blockchain_simulator.py # Điều phối network + các node
│   ├── config.py               # Đọc cấu hình từ config/
│   ├── deterministic_check.py  # Script kiểm tra tính tất định (T8)
│   ├── logger.py               # Log canonical JSONL
│   ├── main.py                 # Entry point: python -m src.main
│   ├── node.py                 # Node tích hợp các module
│   └── scheduler.py            # Virtual-time scheduler
├── tests/                      # Unit test và end-to-end test T1--T8
├── config/
│   ├── simulation.json         # Cấu hình chạy mặc định
│   ├── scenario_unstable_network.json
│   └── README.md               # Mô tả các khóa cấu hình
├── logs/                       # run.jsonl, summary.json sinh ra khi chạy
├── README.md
└── REPORT.pdf
```

Không còn thư mục `scripts/` hay cấu hình hard-code: entry point, checker T8 và
toàn bộ tham số mạng/timeout đều nằm trong `src/` và `config/`.

## 4. Cài đặt và chạy

Yêu cầu Python 3.10+ và chạy mọi lệnh từ **thư mục gốc dự án** (thư mục chứa
`src/`, `tests/`, `config/`):

```powershell
cd Lab01_ID1_ID2_ID3_ID4_ID5
python -m pip install -r requirements.txt
python -m src.main
```

`python -m src.main` là lệnh chạy đầy đủ một scenario: đọc
`config/simulation.json`, tạo validator set, khởi tạo genesis state, ký và nạp
transaction, chạy mạng/consensus đến height yêu cầu, ghi log chuẩn hóa, rồi tự
chạy lại cùng scenario để kiểm tra T8. Kết quả được ghi vào `logs/run.jsonl` và
`logs/summary.json`; thư mục `logs/` được tạo tự động nếu chưa có. Timestamp
trong log là virtual time của simulator, không phải đồng hồ hệ thống.

Mặc định lấy từ `config/simulation.json`: 8 node, seed 0, finalize 3 block, log
`logs/run.jsonl`. Muốn chạy kịch bản mạng bất ổn định (drop/duplicate/delay
trước thời điểm stabilize):

```powershell
python -m src.main --config config/scenario_unstable_network.json
```

Đổi tham số của một run mà không sửa file cấu hình:

```powershell
python -m src.main --nodes 8 --seed 0 --height 3
```

Các tham số dòng lệnh (đều ghi đè lên file cấu hình):

```text
--config  file cấu hình JSON/YAML (mặc định config/simulation.json)
--nodes   số validator (mặc định 8)
--seed    seed tái lập mạng và key mô phỏng (mặc định 0)
--height  số block cần finalize (mặc định 3)
--log     đường dẫn JSONL log (mặc định logs/run.jsonl)
--summary đường dẫn summary (mặc định logs/summary.json)
```

Các tham số mạng (delay, drop rate, duplicate rate, stabilize time, rate limit)
và timeout (base, multiplier, max timeout) nằm trong `config/*.json`; chi tiết
từng khóa xem tại [`config/README.md`](config/README.md).

### 4.1. Luồng chạy một lệnh

1. `src/main.py` đọc `config/simulation.json` (hoặc file `--config`), áp dụng
   tham số dòng lệnh và tạo `SimulationConfig`.
2. `BlockchainSimulator` tạo scheduler, network, validator keys,
   proposer selector và các node độc lập.
3. Transaction được ký bằng Ed25519 và gửi đến mempool của các node.
4. Scheduler gọi node proposer; proposer tạo block trên parent hiện tại.
5. Header được broadcast trước; node nhận kiểm tra proposer, chữ ký, parent,
   transaction và state root trước khi yêu cầu body.
6. Node phát PREVOTE. VotePool kiểm tra chữ ký, domain, height/round/phase và
   loại duplicate hoặc conflicting vote.
7. Quorum PREVOTE tạo polka; node lock block và phát PRECOMMIT.
8. Quorum PRECOMMIT tạo certificate; node kiểm tra certificate, commit block
   đúng một lần và chuyển sang height tiếp theo.
9. Khi đạt `height`, simulator kiểm tra chain, certificate và state root của
   các correct node.
10. Cùng scenario được chạy lại trong bộ nhớ. Hai log canonical và state root
    được so sánh để báo kết quả T8.

Vì vậy sau khi đã cài dependency, người dùng chỉ cần một lệnh chạy chương
trình:

```powershell
python -m src.main
```

## 5. Kiểm tra T1--T8

```powershell
python -m pytest tests -v
python -m src.deterministic_check
```

`python -m pytest tests -v` là điểm chạy kiểm thử duy nhất: nó gọi toàn bộ unit
test (crypto, execution, models, network, consensus) và end-to-end test T1--T8.
`python -m src.deterministic_check` là checker T8 độc lập: chạy cùng scenario
hai lần rồi so sánh từng byte log và state hash, thoát với mã `0` khi mọi điều
kiện đều đạt. Thêm `--config config/scenario_unstable_network.json` (hoặc
`--nodes/--seed/--height`) để kiểm tra một cấu hình khác.

Lệnh `python -m src.main` đã tự kiểm tra T8 cho scenario bình thường. T8 chỉ
đạt khi `logs_byte_identical`, `state_hash_identical`, `all_nodes_agree` và
`completed` đều là `true`.

## 6. Đặc tả Consensus State Machine (TV1, TV2, TV4)

### 6.1. Tham số và thuật ngữ

Consensus được chạy độc lập cho từng `height` và theo các `round` bắt đầu từ
`0`. Với `n = 3f + 1` validator, quorum là:

```text
QUORUM = 2f + 1
```

`nil` là một giá trị vote hợp lệ để báo rằng node không chấp nhận proposal.
`block_id` là hash xác định duy nhất của block (bao gồm `height`, `round`,
`parent_id`, giao dịch và metadata đã canonicalize). Mọi chữ ký phải được
kiểm tra trên payload gồm `height`, `round`, `phase`, `block_id` và `voter_id`.

Trạng thái tối thiểu của một node:

```text
height, round
phase ∈ {PROPOSAL, PREVOTE, PRECOMMIT, FINALIZE}
locked_block_id ∈ {block_id, nil}
locked_round ∈ {integer, nil}
valid_block_id ∈ {block_id, nil}
```

`locked_block_id` không được tự ý thay đổi hoặc xóa trong cùng một height.
`valid_block_id` là block đã có chứng cứ `QUORUM` prevote và có thể dùng để
chọn proposal ở round tiếp theo.

### 6.2. Flow Proposal -> Prevote -> Precommit -> Finalize

Mỗi bước chỉ chuyển tiếp trong cùng `height` và `round`; message đến height
khác phải bị loại trước khi xử lý.

1. **Proposal**
   - Proposer được xác định deterministic từ `(height, round)`.
   - Proposer gửi một block hợp lệ, kèm `parent_id`, `block_id` và chữ ký.
   - Node nhận proposal chỉ chấp nhận khi đúng proposer, đúng height/round,
     parent khớp chain local, chữ ký đúng, giao dịch thực thi hợp lệ và
     `block_id` khớp nội dung.
   - Proposal sai hoặc timeout được xử lý như proposal `nil`; không được
     prevote cho block không hợp lệ.

2. **Prevote**
   - Node gửi **tối đa một** prevote cho `(height, round)`.
   - Nếu proposal hợp lệ và không vi phạm locking rule thì prevote
     `block_id`; ngược lại prevote `nil`.
   - Node đang lock `L` chỉ được prevote `L`, hoặc một block khác `B` khi có
     proof `QUORUM` prevote cho `B` ở round cao hơn `locked_round` (proof of
     valid round). Không có proof thì phải prevote `L`.
   - Nhận đủ `QUORUM` prevote cho cùng một block `B` tạo `polka(B, round)`.

3. **Precommit**
   - Node chỉ gửi **tối đa một** precommit cho `(height, round)`.
   - Khi có `polka(B, round)`, node lock `B` tại `round` và precommit `B`.
   - Nếu không có polka trước timeout, node precommit `nil` (hoặc chuyển round
     theo cơ chế timeout của scheduler); không được precommit một block chỉ
     vì đã thấy proposal.
   - Precommit cho `B` phải kèm hoặc truy xuất được `polka(B, round)`.

4. **Finalize**
   - Block `B` chỉ được finalize khi có `QUORUM` precommit hợp lệ cho cùng
     `(height, round, B)`.
   - Node ghi `B` vào chain, áp dụng state transition đúng một lần, phát
     `Finalize(height, block_id, certificate)` và chuyển sang
     `height + 1`, `round = 0`, `phase = PROPOSAL`.
   - Sau finalize, mọi proposal/vote của height cũ bị loại. Không finalize
     block khác nếu height đó đã finalized.

Luồng tóm tắt:

```text
PROPOSAL
   | proposal hợp lệ + không vi phạm lock
   v
PREVOTE -- QUORUM prevote (polka) --> PRECOMMIT
   | timeout / không đủ polka              |
   +--------------> round tiếp theo <-----+
                         |
              QUORUM precommit cho B
                         v
                     FINALIZE
```

### 6.3. Lock, unlock và an toàn

- **Lock:** chỉ lock khi node quan sát `QUORUM` prevote cho một block. Khi
  lock `B`, ghi cả `locked_block_id = B` và `locked_round`.
- **Giữ lock:** ở các round sau, node tiếp tục prevote `B` nếu không có proof
  hợp lệ cho block khác.
- **Unlock:** chỉ unlock/chuyển từ `B` sang `C` khi có `polka(C, r_new)` với
  `r_new > locked_round`. Việc nhận proposal mới, timeout, hoặc thấy một
  precommit đơn lẻ không đủ điều kiện unlock.
- **Nil không mở lock:** prevote/precommit `nil` không tạo lock và không xóa
  lock hiện tại.
- **Safety:** hai block khác nhau cùng height không thể cùng có quorum
  precommit, vì hai quorum `2f + 1` giao nhau ở ít nhất `f + 1` validator,
  trong đó phải có ít nhất một validator đúng; validator đúng không vote
  xung đột và tuân thủ lock.

### 6.4. Duplicate guard và điều kiện loại message

Mỗi vote được deduplicate bằng khóa:

```text
(height, round, phase, voter_id)
```

Node phải bỏ qua (và log lý do) khi message:

- trùng khóa trên, kể cả payload khác;
- voter không thuộc validator set hoặc chữ ký không hợp lệ;
- `height` đã finalized, `round` không hợp lệ, hoặc phase không đúng;
- `block_id` không khớp nội dung/proof;
- precommit không có `polka` tương ứng;
- vote nil có payload block/proof không hợp lệ.

Vote trùng không được tăng counter, tạo lại lock, phát lại event hoặc áp dụng
state transition. Các map counter phải đếm theo `voter_id`, không đếm theo số
message nhận được. Conflicting vote của cùng một voter được ghi nhận là
vi phạm Byzantine nhưng vẫn chỉ tính tối đa một vote trong mỗi chứng cứ.

### 6.5. Hợp đồng kiểm thử tối thiểu

TV4 cần kiểm tra ít nhất các trường hợp sau:

- proposal hợp lệ đi đủ bốn phase và finalize đúng một lần;
- proposal sai, timeout và `nil` không tạo lock;
- node đã lock `B` không prevote `C` nếu thiếu higher-round polka;
- higher-round polka cho phép unlock/chuyển lock đúng một lần;
- duplicate và conflicting vote không làm tăng quorum;
- không finalize với `2f` precommit hoặc precommit thiếu polka;
- hai block khác nhau cùng height không thể cùng finalize;
- message cũ/sai height sau finalize không làm thay đổi state.
