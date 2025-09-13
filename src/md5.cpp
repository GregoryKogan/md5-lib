#include "md5.h"

#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <vector>

namespace {

using uint32 = std::uint32_t;
using uint64 = std::uint64_t;

constexpr uint32 S11 = 7, S12 = 12, S13 = 17, S14 = 22;
constexpr uint32 S21 = 5, S22 = 9, S23 = 14, S24 = 20;
constexpr uint32 S31 = 4, S32 = 11, S33 = 16, S34 = 23;
constexpr uint32 S41 = 6, S42 = 10, S43 = 15, S44 = 21;

constexpr std::array<uint32, 64> T = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a,
    0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340,
    0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8,
    0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
    0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391};

constexpr uint32 F(uint32 x, uint32 y, uint32 z) { return (x & y) | (~x & z); }
constexpr uint32 G(uint32 x, uint32 y, uint32 z) { return (x & z) | (y & ~z); }
constexpr uint32 H(uint32 x, uint32 y, uint32 z) { return x ^ y ^ z; }
constexpr uint32 I(uint32 x, uint32 y, uint32 z) { return y ^ (x | ~z); }

constexpr uint32 rotate_left(uint32 x, uint32 n) {
  return (x << n) | (x >> (32 - n));
}

class MD5_CTX {
 public:
  MD5_CTX();

  void update(const unsigned char* data, std::size_t size);

  [[nodiscard]] std::array<unsigned char, 16> finalize();

 private:
  void transform(const unsigned char block[64]);

  static void encode(unsigned char* dest, const uint32* src, std::size_t len);
  static void decode(uint32* dest, const unsigned char* src, std::size_t len);

  std::array<uint32, 4> state_ = {0x67452301, 0xefcdab89, 0x98badcfe,
                                  0x10325476};
  uint64 bit_count_ = 0;
  std::array<unsigned char, 64> buffer_{};
  std::size_t buffer_used_ = 0;
};

MD5_CTX::MD5_CTX() = default;

void MD5_CTX::update(const unsigned char* data, const std::size_t size) {
  bit_count_ += (static_cast<uint64>(size) * 8);

  std::size_t data_offset = 0;

  if (buffer_used_ > 0) {
    const std::size_t space_in_buffer = 64 - buffer_used_;
    const std::size_t bytes_to_copy = std::min(size, space_in_buffer);

    std::memcpy(buffer_.data() + buffer_used_, data, bytes_to_copy);
    buffer_used_ += bytes_to_copy;
    data_offset += bytes_to_copy;

    if (buffer_used_ == 64) {
      transform(buffer_.data());
      buffer_used_ = 0;
    }
  }

  while (size - data_offset >= 64) {
    transform(data + data_offset);
    data_offset += 64;
  }

  const std::size_t remaining = size - data_offset;
  if (remaining > 0) {
    std::memcpy(buffer_.data(), data + data_offset, remaining);
    buffer_used_ = remaining;
  }
}

[[nodiscard]] std::array<unsigned char, 16> MD5_CTX::finalize() {
  std::array<unsigned char, 8> bit_count_bytes{};
  encode(bit_count_bytes.data(), reinterpret_cast<uint32*>(&bit_count_), 8);

  const unsigned char padding_start[1] = {0x80};
  update(padding_start, 1);

  const std::size_t current_padding = (56 - buffer_used_) % 64;
  static const unsigned char zero_padding[64] = {0};
  update(zero_padding, current_padding);

  update(bit_count_bytes.data(), 8);

  std::array<unsigned char, 16> digest{};
  encode(digest.data(), state_.data(), 16);

  *this = MD5_CTX();

  return digest;
}

void MD5_CTX::encode(unsigned char* dest, const uint32* src, std::size_t len) {
  for (std::size_t i = 0, j = 0; j < len; i++, j += 4) {
    dest[j] = static_cast<unsigned char>(src[i] & 0xff);
    dest[j + 1] = static_cast<unsigned char>((src[i] >> 8) & 0xff);
    dest[j + 2] = static_cast<unsigned char>((src[i] >> 16) & 0xff);
    dest[j + 3] = static_cast<unsigned char>((src[i] >> 24) & 0xff);
  }
}

void MD5_CTX::decode(uint32* dest, const unsigned char* src, std::size_t len) {
  for (std::size_t i = 0, j = 0; j < len; i++, j += 4) {
    dest[i] = (static_cast<uint32>(src[j])) |
              (static_cast<uint32>(src[j + 1]) << 8) |
              (static_cast<uint32>(src[j + 2]) << 16) |
              (static_cast<uint32>(src[j + 3]) << 24);
  }
}

void MD5_CTX::transform(const unsigned char block[64]) {
  uint32 a = state_[0], b = state_[1], c = state_[2], d = state_[3];
  std::array<uint32, 16> x{};
  decode(x.data(), block, 64);

#define MD5_TRANSFORM_STEP(f, a, b, c, d, k, s, i) \
  (a) = rotate_left((a) + f((b), (c), (d)) + x[(k)] + T[(i) - 1], (s)) + (b)

  // Round 1
  MD5_TRANSFORM_STEP(F, a, b, c, d, 0, S11, 1);
  MD5_TRANSFORM_STEP(F, d, a, b, c, 1, S12, 2);
  MD5_TRANSFORM_STEP(F, c, d, a, b, 2, S13, 3);
  MD5_TRANSFORM_STEP(F, b, c, d, a, 3, S14, 4);
  MD5_TRANSFORM_STEP(F, a, b, c, d, 4, S11, 5);
  MD5_TRANSFORM_STEP(F, d, a, b, c, 5, S12, 6);
  MD5_TRANSFORM_STEP(F, c, d, a, b, 6, S13, 7);
  MD5_TRANSFORM_STEP(F, b, c, d, a, 7, S14, 8);
  MD5_TRANSFORM_STEP(F, a, b, c, d, 8, S11, 9);
  MD5_TRANSFORM_STEP(F, d, a, b, c, 9, S12, 10);
  MD5_TRANSFORM_STEP(F, c, d, a, b, 10, S13, 11);
  MD5_TRANSFORM_STEP(F, b, c, d, a, 11, S14, 12);
  MD5_TRANSFORM_STEP(F, a, b, c, d, 12, S11, 13);
  MD5_TRANSFORM_STEP(F, d, a, b, c, 13, S12, 14);
  MD5_TRANSFORM_STEP(F, c, d, a, b, 14, S13, 15);
  MD5_TRANSFORM_STEP(F, b, c, d, a, 15, S14, 16);

  // Round 2
  MD5_TRANSFORM_STEP(G, a, b, c, d, 1, S21, 17);
  MD5_TRANSFORM_STEP(G, d, a, b, c, 6, S22, 18);
  MD5_TRANSFORM_STEP(G, c, d, a, b, 11, S23, 19);
  MD5_TRANSFORM_STEP(G, b, c, d, a, 0, S24, 20);
  MD5_TRANSFORM_STEP(G, a, b, c, d, 5, S21, 21);
  MD5_TRANSFORM_STEP(G, d, a, b, c, 10, S22, 22);
  MD5_TRANSFORM_STEP(G, c, d, a, b, 15, S23, 23);
  MD5_TRANSFORM_STEP(G, b, c, d, a, 4, S24, 24);
  MD5_TRANSFORM_STEP(G, a, b, c, d, 9, S21, 25);
  MD5_TRANSFORM_STEP(G, d, a, b, c, 14, S22, 26);
  MD5_TRANSFORM_STEP(G, c, d, a, b, 3, S23, 27);
  MD5_TRANSFORM_STEP(G, b, c, d, a, 8, S24, 28);
  MD5_TRANSFORM_STEP(G, a, b, c, d, 13, S21, 29);
  MD5_TRANSFORM_STEP(G, d, a, b, c, 2, S22, 30);
  MD5_TRANSFORM_STEP(G, c, d, a, b, 7, S23, 31);
  MD5_TRANSFORM_STEP(G, b, c, d, a, 12, S24, 32);

  // Round 3
  MD5_TRANSFORM_STEP(H, a, b, c, d, 5, S31, 33);
  MD5_TRANSFORM_STEP(H, d, a, b, c, 8, S32, 34);
  MD5_TRANSFORM_STEP(H, c, d, a, b, 11, S33, 35);
  MD5_TRANSFORM_STEP(H, b, c, d, a, 14, S34, 36);
  MD5_TRANSFORM_STEP(H, a, b, c, d, 1, S31, 37);
  MD5_TRANSFORM_STEP(H, d, a, b, c, 4, S32, 38);
  MD5_TRANSFORM_STEP(H, c, d, a, b, 7, S33, 39);
  MD5_TRANSFORM_STEP(H, b, c, d, a, 10, S34, 40);
  MD5_TRANSFORM_STEP(H, a, b, c, d, 13, S31, 41);
  MD5_TRANSFORM_STEP(H, d, a, b, c, 0, S32, 42);
  MD5_TRANSFORM_STEP(H, c, d, a, b, 3, S33, 43);
  MD5_TRANSFORM_STEP(H, b, c, d, a, 6, S34, 44);
  MD5_TRANSFORM_STEP(H, a, b, c, d, 9, S31, 45);
  MD5_TRANSFORM_STEP(H, d, a, b, c, 12, S32, 46);
  MD5_TRANSFORM_STEP(H, c, d, a, b, 15, S33, 47);
  MD5_TRANSFORM_STEP(H, b, c, d, a, 2, S34, 48);

  // Round 4
  MD5_TRANSFORM_STEP(I, a, b, c, d, 0, S41, 49);
  MD5_TRANSFORM_STEP(I, d, a, b, c, 7, S42, 50);
  MD5_TRANSFORM_STEP(I, c, d, a, b, 14, S43, 51);
  MD5_TRANSFORM_STEP(I, b, c, d, a, 5, S44, 52);
  MD5_TRANSFORM_STEP(I, a, b, c, d, 12, S41, 53);
  MD5_TRANSFORM_STEP(I, d, a, b, c, 3, S42, 54);
  MD5_TRANSFORM_STEP(I, c, d, a, b, 10, S43, 55);
  MD5_TRANSFORM_STEP(I, b, c, d, a, 1, S44, 56);
  MD5_TRANSFORM_STEP(I, a, b, c, d, 8, S41, 57);
  MD5_TRANSFORM_STEP(I, d, a, b, c, 15, S42, 58);
  MD5_TRANSFORM_STEP(I, c, d, a, b, 6, S43, 59);
  MD5_TRANSFORM_STEP(I, b, c, d, a, 13, S44, 60);
  MD5_TRANSFORM_STEP(I, a, b, c, d, 4, S41, 61);
  MD5_TRANSFORM_STEP(I, d, a, b, c, 11, S42, 62);
  MD5_TRANSFORM_STEP(I, c, d, a, b, 2, S43, 63);
  MD5_TRANSFORM_STEP(I, b, c, d, a, 9, S44, 64);

#undef MD5_TRANSFORM_STEP

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
}

std::string format_digest(const std::array<unsigned char, 16>& digest) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (const auto byte : digest) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

}  // namespace

namespace md5_lib {

std::string calculate_md5(std::istream& stream) {
  MD5_CTX context;

  std::vector<char> buffer(8192);
  while (stream.good()) {
    stream.read(buffer.data(), buffer.size());
    const auto bytes_read = stream.gcount();
    if (bytes_read > 0) {
      context.update(reinterpret_cast<const unsigned char*>(buffer.data()),
                     static_cast<std::size_t>(bytes_read));
    }
  }

  if (stream.bad()) {
    throw std::ios_base::failure("Stream read error.");
  }

  const auto digest = context.finalize();
  return format_digest(digest);
}

std::string calculate_md5(const unsigned char* data, const std::size_t size) {
  if (data == nullptr && size > 0) {
    throw std::invalid_argument("Data pointer is null but size is non-zero.");
  }

  MD5_CTX context;
  context.update(data, size);
  const auto digest = context.finalize();
  return format_digest(digest);
}

}  // namespace md5_lib