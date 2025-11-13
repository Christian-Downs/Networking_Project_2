# ✅ CS447 P2: Distributed FTP Server — Progress Tracker

## 🧭 Phase 1 — Core FTP Compliance (RFC 959)

### FTP Control Commands
- [x] Implement `USER` (anonymous login)
- [x] Implement `PWD`
- [x] Implement `CWD`
- [x] Implement `CDUP`
- [x] Implement `QUIT`

### Data Channel
- [ ] Implement `PASV`
  - [ ] Create and bind ephemeral port.
  - [ ] Send `227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)` response.
  - [ ] Store active data socket for current session.
  - [ ] Auto-close data socket after each `LIST` or `RETR`.
- [ ] Implement `LIST`
  - [ ] Verify PASV session exists or reply `425`.
  - [ ] Send listing via data socket using `std::filesystem`.
  - [ ] Reply sequence: `150` → data → `226`.
- [ ] Implement `RETR`
  - [ ] Verify PASV session or reply `425`.
  - [ ] Open and stream file from jailed `db/` folder.
  - [ ] Handle missing file with `550`.

## 🌐 Phase 2 — P2P Distributed Layer

- [ ] Implement peer login `USER peer@<ip>`
  - [ ] Compare `<ip>` with `their_addr`.
  - [ ] Reply `230` or `530`.
- [ ] Implement background peer discovery thread
  - [ ] Parse `PEER_SUBNET` and `PORT` from `server.conf`.
  - [ ] Scan subnet on `PORT + 200`.
  - [ ] Maintain `peer_file_map`.
- [ ] Implement unified `LIST`
  - [ ] Gather local and peer listings.
  - [ ] Merge into unified output (tag entries as `local` or `peer`).
- [ ] Implement distributed `RETR`
  - [ ] Forward `PASV` and `RETR` requests to peer server.
  - [ ] Redirect client using peer’s `227` and `226` responses.

## ⚙️ Phase 3 — Reliability & Security

- [ ] Jail server to `db/` directory (block `..` traversal)
- [ ] Implement robust error codes (425, 450, 451, 500, 503, 550, etc.)
- [ ] Detect and remove disconnected peers from map.

## 📘 Phase 4 — Documentation & Testing

- [ ] Create `README.md` with:
  - [ ] Compilation instructions
  - [ ] Example session logs
  - [ ] Peer network explanation
- [ ] Create report PDF with screenshots for Moodle.
- [ ] Verify all tests in `ftp_tests` pass:
  - [ ] USER tests
  - [ ] PWD/CWD/CDUP tests
  - [ ] PASV/LIST/RETR tests
  - [ ] P2P distributed LIST test
