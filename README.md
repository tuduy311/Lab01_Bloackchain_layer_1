# Lab 01 - Blockchain Layer 1 Simulator

## Mục tiêu

Mô phỏng blockchain tài khoản với nhiều validator độc lập. Mỗi node giữ ledger,
state và mempool riêng; node chỉ trao đổi proposal, vote, transaction và
certificate qua mạng sự kiện. Mạng hỗ trợ trễ, mất, đảo thứ tự, gửi trùng, giới
hạn tốc độ và chuyển sang đồng bộ sau `stabilize_at`.

## Cấu trúc

```text
src/
  blockchain_simulator.py  cấu hình và vòng chạy mô phỏng
  node.py                  node validator, ledger, mempool, message handler
  logger.py                log JSONL ổn định
  scheduler.py             bộ lập lịch sự kiện giả lập
  models/                  block, transaction, vote, certificate
  crypto/                  SHA-256, Ed25519 và domain separation
  execution/               account state, kiểm tra và áp dụng giao dịch
  consensus/               proposer, lock, quorum, timeout và state machine
    vote_pool.py           vote storage, loại trùng và ghi nhận equivocation
  network/                 vận chuyển, fault injection, rate limit, header/body
  logger.py                log JSONL ổn định
tests/                     unit test và T1-T8 end-to-end
config/                    cấu hình mặc định
scenarios/                 cấu hình tái lập cho T1-T8
scripts/deterministic_check.py
main.py                    entry point duy nhất
logs/                      log và snapshot sinh ra khi chạy
```

## Thiết kế chính

- Giao dịch là chuyển số dư có chữ ký của sender, nonce tuần tự và domain
  `TX:<chain_id>`.
- Block ID cam kết `chain_id`, height, parent, thứ tự giao dịch và state root.
  Header được ký trong domain `HEADER:<chain_id>`; round và proposer được ký
  riêng để cùng một giá trị block có thể được đề xuất lại ở round sau.
- Vote ký height, round, phase, block ID, voter và chain trong domain
  `VOTE:<chain_id>`. Vote trùng không tăng quorum; vote xung đột của cùng
  validator được ghi nhận nhưng chỉ vote đầu tiên được tính.
- Node chỉ lock khi có quorum prevote. Muốn đổi lock, proposal phải mang polka
  hợp lệ ở round cao hơn. Finalize certificate chứa cả quorum prevote và
  precommit để node khác xác minh độc lập.
- Với `f = floor((n-1)/3)`, quorum dùng `n-f`. Khi `n=3f+1`, giá trị này bằng
  `2f+1`; cách tính này cũng giữ giao quorum an toàn cho topology 8 node.
- Proposal dùng handshake header trước body. Receiver kiểm tra header, chấp
  nhận header rồi mới yêu cầu body.
- Scheduler dùng tick nguyên nanosecond; RNG mạng và leader ring được tách
  stream theo seed. Log JSONL dùng encoding ổn định để so sánh byte-for-byte.

## Cài đặt và chạy

Yêu cầu Python 3.10 trở lên.

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
```

Chạy cấu hình mặc định. Kết quả được ghi vào `logs/run.jsonl` và
`logs/blockchain.json`:

```powershell
py main.py --config config/default.json
```

Chạy một kịch bản và đặt tên riêng cho đầu ra:

```powershell
py main.py --config scenarios/T5_pre_synchrony_faults.json `
  --log logs/T5.jsonl --state logs/T5_blockchain.json
```

Chạy toàn bộ unit test và end-to-end test qua cùng entry point:

```powershell
py main.py --test
```

Chạy cùng cấu hình hai lần, so sánh byte của log và final state hash:

```powershell
py main.py --config scenarios/T8_replay.json --check-determinism
```

Có thể gọi riêng bộ kiểm tra tái lập:

```powershell
py scripts/deterministic_check.py --config scenarios/T8_replay.json
```

Exit code `0` nghĩa là mô phỏng hội tụ và an toàn theo các kiểm tra của chương
trình; exit code `2` nghĩa là chưa hội tụ hoặc phát hiện xung đột finalize.

## Kịch bản kiểm thử

| ID | Kịch bản | Kết quả được kiểm tra |
|---|---|---|
| T1 | Mạng bình thường | Ledger và state root hội tụ |
| T2 | Message trùng và đảo thứ tự | Không đếm vote hai lần, ledger hội tụ |
| T3 | Chữ ký sai và sai chain domain | Vote bị từ chối và log lý do |
| T4 | Gửi lại transaction | Transaction chỉ được áp dụng một lần |
| T5 | Mất/trễ message trước đồng bộ | Không finalize xung đột, hội tụ sau đồng bộ |
| T6 | Proposer im lặng | Timeout đổi round, proposer sau tiếp tục |
| T7 | Proposer Byzantine gửi hai proposal/vote | Không có hai block finalize cùng height |
| T8 | Chạy lại cùng seed | Log giống từng byte và state hash trùng |

## Khóa của cấu hình demo

Cấu hình mặc định dùng khóa fixture cố định để log và chữ ký có thể tái lập.
Các khóa này công khai trong mã nguồn và chỉ dành cho simulator; không dùng
trong hệ thống thật. Có thể truyền `validator_private_keys` và
`participant_private_keys` trong JSON để thay fixture. Seed của mạng không được
dùng làm nguồn sinh khóa mật mã.
