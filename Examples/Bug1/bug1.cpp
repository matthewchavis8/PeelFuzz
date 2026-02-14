#include <cstring>
#include <cstdint>
#include <iostream>
#include "../../Driver/fuzzer.h"


struct Header {
  uint8_t  magic[4];    // must be { 0xDE, 0xAD, 0xBE, 0xEF }
  uint8_t  version;
  uint8_t  xor_check;   // XOR fold of payload
  uint16_t length;      // payload length
  uint16_t crc;         // CRC-16 of payload
  uint16_t reserved;    // must be 0x0000
};

static int iterations = 0;

// CRC-16 (CRC-CCITT)
static uint16_t crc16(const uint8_t* data, size_t len) {
  uint16_t crc = 0xFFFF;
  for (size_t i = 0; i < len; i++) {
    crc ^= (uint16_t)data[i] << 8;
    for (int j = 0; j < 8; j++) {
      if (crc & 0x8000)
        crc = (crc << 1) ^ 0x1021;
      else
        crc <<= 1;
    }
  }
  return crc;
}

// XOR fold: reduces data to a single byte
static uint8_t xor_fold(const uint8_t* data, size_t len) {
  uint8_t x = 0;
  for (size_t i = 0; i < len; i++)
    x ^= data[i];
  return x;
}

// Non-linear scramble
static uint8_t scramble(uint8_t a, uint8_t b) {
  return ((a * 7) ^ (b + 0x55)) & 0xFF;
}

// djb2-variant hash, truncated to 16 bits
static uint16_t mini_hash(const uint8_t* data, size_t len) {
  uint32_t h = 5381;
  for (size_t i = 0; i < len; i++)
    h = ((h << 5) + h) + data[i];
  return (uint16_t)(h & 0xFFFF);
}

// Rotate left on a byte
static uint8_t rol8(uint8_t v, int n) {
  return (uint8_t)((v << n) | (v >> (8 - n)));
}

// XTEA-like 2-round transform on a 64-bit block
static void xtea_transform(uint32_t v[2], uint32_t key[4]) {
  uint32_t v0 = v[0], v1 = v[1];
  uint32_t delta = 0x9E3779B9, sum = 0;
  for (int i = 0; i < 2; i++) {
    sum += delta;
    v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
  }
  v[0] = v0;
  v[1] = v1;
}

void parse_packet(const uint8_t* data, size_t len) {
  iterations++;


  // Gate 1: minimum size for header
  if (len < sizeof(Header))
    return;

  Header hdr;
  std::memcpy(&hdr, data, sizeof(Header));

  // Gate 2: 4-byte magic sequence
  if (hdr.magic[0] != 0xDE || hdr.magic[1] != 0xAD ||
      hdr.magic[2] != 0xBE || hdr.magic[3] != 0xEF)
    return;

  // Gate 3: version in {1, 2, 3}
  if (hdr.version < 1 || hdr.version > 3)
    return;

  // Gate 4: reserved field must be zero
  if (hdr.reserved != 0x0000)
    return;

  const uint8_t* payload = data + sizeof(Header);
  size_t payload_len = len - sizeof(Header);

  // Gate 5: length field must match actual payload
  if (hdr.length != payload_len)
    return;

  // Gate 6: CRC-16 must match
  if (hdr.crc != crc16(payload, payload_len))
    return;

  // Gate 7: XOR fold of payload must match
  if (hdr.xor_check != xor_fold(payload, payload_len))
    return;

  if (hdr.version == 1) {
    // V1.1: need at least 24 bytes of payload
    if (payload_len < 24)
      return;

    // V1.2: first 4 bytes must spell "FUZZ"
    if (payload[0] != 'F' || payload[1] != 'U' ||
        payload[2] != 'Z' || payload[3] != 'Z')
      return;

    // V1.3: bytes 4-5 as uint16 must equal mini_hash of bytes 0-3
    uint16_t h1;
    std::memcpy(&h1, payload + 4, 2);
    if (h1 != mini_hash(payload, 4))
      return;

    // V1.4: byte 6 = scramble(payload[4], payload[5])
    if (payload[6] != scramble(payload[4], payload[5]))
      return;

    // V1.5: bytes 7-10 — system of equations:
    //   b7 + b8 == 0xFF
    //   b8 ^ b9 == 0x3C
    //   b9 * b10 == 0x90 (mod 256)
    //   b10 - b7 == 0x15 (mod 256)
    uint8_t b7 = payload[7], b8 = payload[8];
    uint8_t b9 = payload[9], b10 = payload[10];
    if ((uint8_t)(b7 + b8) != 0xFF)
      return;
    if ((b8 ^ b9) != 0x3C)
      return;
    if ((uint8_t)(b9 * b10) != 0x90)
      return;
    if ((uint8_t)(b10 - b7) != 0x15)
      return;

    // V1.6: bytes 11-12 = CRC-16 of bytes 0-10 (inner CRC)
    uint16_t inner_crc;
    std::memcpy(&inner_crc, payload + 11, 2);
    if (inner_crc != crc16(payload, 11))
      return;

    // V1.7: rotation chain — each byte is a rotated version of an earlier byte
    //   b13 = ROL(b7, 3),  b14 = ROL(b8, 5),  b15 = ROL(b9, 1)
    if (payload[13] != rol8(b7, 3))
      return;
    if (payload[14] != rol8(b8, 5))
      return;
    if (payload[15] != rol8(b9, 1))
      return;

    // V1.8: byte 16 = XOR of bytes 0-15
    uint8_t xcheck = 0;
    for (int i = 0; i < 16; i++)
      xcheck ^= payload[i];
    if (payload[16] != xcheck)
      return;

    // V1.9: bytes 17-20 as uint32 must equal 0xDEADC0DE
    uint32_t magic32;
    std::memcpy(&magic32, payload + 17, 4);
    if (magic32 != 0xDEADC0DE)
      return;

    // V1.10: sum of all 24 bytes mod 251 (prime) must be 0
    //        — bytes 21-23 are "free" to satisfy this
    uint32_t total = 0;
    for (int i = 0; i < 24; i++)
      total += payload[i];
    if (total % 251 != 0)
      return;

    std::cout << "[BUG 1] Ultra arithmetic maze solved — iteration "
              << iterations << '\n';
    int* bad = nullptr;
    *bad = 0xDEAD;
  }

  // ================================================================
  //  VERSION 2 — Deep Nested Command Protocol  (10 more gates)
  // ================================================================
  if (hdr.version == 2) {
    // V2.1: need at least 28 bytes
    if (payload_len < 28)
      return;

    uint8_t cmd    = payload[0];
    uint8_t subcmd = payload[1];
    uint8_t auth   = payload[2];
    uint8_t flags  = payload[3];

    // V2.2: cmd must be 0x42
    if (cmd != 0x42)
      return;

    // V2.3: subcmd from lookup table {0x0A, 0x0B, 0x0C}
    static const uint8_t valid_subcmds[] = {0x0A, 0x0B, 0x0C};
    bool subcmd_ok = false;
    for (auto v : valid_subcmds)
      if (subcmd == v) subcmd_ok = true;
    if (!subcmd_ok)
      return;

    // V2.4: auth = scramble(cmd, subcmd)
    if (auth != scramble(cmd, subcmd))
      return;

    // V2.5: flags — bits 0,3,6 must be set; bits 5,7 must be clear
    if ((flags & 0x49) != 0x49 || (flags & 0xA0))
      return;

    // V2.6: bytes 4-5 as uint16 = mini_hash of bytes 0-3
    uint16_t seq;
    std::memcpy(&seq, payload + 4, 2);
    if (seq != mini_hash(payload, 4))
      return;

    // V2.7: bytes 6-9 are a "session key" whose mini_hash must == 0xBEEF
    if (mini_hash(payload + 6, 4) != 0xBEEF)
      return;

    // V2.8: bytes 10-11 = CRC-16 of bytes 0-9
    uint16_t inner_crc;
    std::memcpy(&inner_crc, payload + 10, 2);
    if (inner_crc != crc16(payload, 10))
      return;

    // V2.9: bytes 12-19 — four XOR-pairs, each XOR to 0xAA,
    //        each pair's first byte > 0xC0
    for (int i = 12; i < 20; i += 2) {
      if ((payload[i] ^ payload[i + 1]) != 0xAA)
        return;
      if (payload[i] <= 0xC0)
        return;
    }

    // V2.10: bytes 20-27 form two uint32s — after 2-round XTEA with
    //        key derived from [cmd, subcmd, auth, flags],
    //        low 16 bits of v[0] must equal 0x1337
    uint32_t v[2], key[4];
    std::memcpy(v, payload + 20, 8);
    key[0] = cmd; key[1] = subcmd; key[2] = auth; key[3] = flags;
    uint32_t vc[2] = {v[0], v[1]};
    xtea_transform(vc, key);
    if ((vc[0] & 0xFFFF) != 0x1337)
      return;

    std::cout << "[BUG 2] Deep command protocol breached — iteration "
              << iterations << '\n';
    char small[4];
    std::memcpy(small, payload + 12, payload_len - 12);  // buffer overflow
  }

  // ================================================================
  //  VERSION 3 — Multi-layer Crypto Challenge  (10 more gates)
  // ================================================================
  if (hdr.version == 3) {
    // V3.1: need at least 32 bytes
    if (payload_len < 32)
      return;

    // V3.2: first 4 bytes = "PEEL"
    if (payload[0] != 'P' || payload[1] != 'E' ||
        payload[2] != 'E' || payload[3] != 'L')
      return;

    // V3.3: bytes 4-7 as uint32 must be 0x00010007
    uint32_t token;
    std::memcpy(&token, payload + 4, sizeof(token));
    if (token != 0x00010007)
      return;

    // V3.4: bytes 8-11 — chained constraints:
    //   b8 + b9 == 0xFF
    //   b9 * b10 == 0x20 (mod 256)
    //   b10 ^ b11 == 0x3C
    //   b11 & 0x0F == 0x08
    uint8_t b8 = payload[8], b9 = payload[9];
    uint8_t b10 = payload[10], b11 = payload[11];
    if ((uint8_t)(b8 + b9) != 0xFF)
      return;
    if ((uint8_t)(b9 * b10) != 0x20)
      return;
    if ((b10 ^ b11) != 0x3C)
      return;
    if ((b11 & 0x0F) != 0x08)
      return;

    // V3.5: bytes 12-13 = CRC-16 of bytes 0-11
    uint16_t crc1;
    std::memcpy(&crc1, payload + 12, 2);
    if (crc1 != crc16(payload, 12))
      return;

    // V3.6: bytes 14-15 = CRC-16 of bytes 0-13 (CASCADED — CRC over CRC!)
    uint16_t crc2;
    std::memcpy(&crc2, payload + 14, 2);
    if (crc2 != crc16(payload, 14))
      return;

    // V3.7: bytes 16-19 as uint32 must equal mini_hash of bytes 0-15
    uint32_t stored_hash;
    std::memcpy(&stored_hash, payload + 16, 4);
    if (stored_hash != (uint32_t)mini_hash(payload, 16))
      return;

    // V3.8: bytes 20-23 — rotation chain:
    //   each byte[i] == ROL(byte[i-4], (i % 3) + 1)
    for (int i = 20; i < 24; i++) {
      if (payload[i] != rol8(payload[i - 4], (i % 3) + 1))
        return;
    }

    // V3.9: bytes 24-27 as uint32 = 0xCAFEBABE
    uint32_t magic;
    std::memcpy(&magic, payload + 24, 4);
    if (magic != 0xCAFEBABE)
      return;

    // V3.10: bytes 28-31 = CRC-16 of bytes 0-27, stored twice (redundancy)
    uint16_t final_crc = crc16(payload, 28);
    uint16_t fc1, fc2;
    std::memcpy(&fc1, payload + 28, 2);
    std::memcpy(&fc2, payload + 30, 2);
    if (fc1 != final_crc || fc2 != final_crc)
      return;

    std::cout << "[BUG 3] Multi-layer crypto breached — iteration "
              << iterations << '\n';
    int x = 1 / (int)(payload[8] - b8);  // division by zero
    (void)x;
  }
  int* x = nullptr;
  *x = 200;
}

int main() {
  // Explicit multi-core configuration for better performance
  PeelFuzzConfig config = {
    .harness_type = HARNESS_BYTES,
    .target_fn = (void*)parse_packet,
    .scheduler_type = SCHEDULER_WEIGHTED,  // or SCHEDULER_WEIGHTED
    .timeout_ms = 1000,
    .crash_dir = nullptr,  // use default "./crashes"
    .seed_count = 16,      // more seeds for better coverage
    .core_count = 10,      // explicit: use all 10 cores
    .use_tui = false
  };

  peel_fuzz_run(&config);
  return 0;
}
