#include "md5.h"

#include <gtest/gtest.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

class RFC1321TestVectors : public ::testing::Test {};

void RunTest(const std::string& input, const std::string& expected_hash) {
  // 1. Test the memory-based API
  const std::string hash_mem = md5_lib::calculate_md5(
      reinterpret_cast<const unsigned char*>(input.data()), input.size());
  EXPECT_EQ(hash_mem, expected_hash);

  // 2. Test the stream-based API
  std::stringstream ss(input);
  const std::string hash_stream = md5_lib::calculate_md5(ss);
  EXPECT_EQ(hash_stream, expected_hash);
}

TEST_F(RFC1321TestVectors, EmptyString) {
  RunTest("", "d41d8cd98f00b204e9800998ecf8427e");
}

TEST_F(RFC1321TestVectors, a) {
  RunTest("a", "0cc175b9c0f1b6a831c399e269772661");
}

TEST_F(RFC1321TestVectors, abc) {
  RunTest("abc", "900150983cd24fb0d6963f7d28e17f72");
}

TEST_F(RFC1321TestVectors, MessageDigest) {
  RunTest("message digest", "f96b697d7cb7938d525a2f31aaf161d0");
}

TEST_F(RFC1321TestVectors, LowercaseAlphabet) {
  RunTest("abcdefghijklmnopqrstuvwxyz", "c3fcd3d76192e4007dfb496cca67e13b");
}

TEST_F(RFC1321TestVectors, Alphanumeric) {
  RunTest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
          "d174ab98d277d9f5a5611c2c9f419d9f");
}

TEST_F(RFC1321TestVectors, LongStringOfNumbers) {
  RunTest(
      "123456789012345678901234567890123456789012345678901234567890123456789012"
      "34567890",
      "57edf4a22be3c955ac49da2e2107b67a");
}

class BoundaryConditionTests : public ::testing::Test {};

TEST_F(BoundaryConditionTests, LessThanOneBlock_PaddingBoundary_55_Bytes) {
  std::string input(55, 'a');
  RunTest(input, "ef1772b6dff9a122358552954ad0df65");
}

TEST_F(BoundaryConditionTests, LessThanOneBlock_PaddingBoundary_56_Bytes) {
  std::string input(56, 'a');
  RunTest(input, "3b0c8ac703f828b04c6c197006d17218");
}

TEST_F(BoundaryConditionTests, LessThanOneBlock_PaddingBoundary_63_Bytes) {
  std::string input(63, 'a');
  RunTest(input, "b06521f39153d618550606be297466d5");
}

TEST_F(BoundaryConditionTests, ExactlyOneBlock_64_Bytes) {
  std::string input(64, 'a');
  RunTest(input, "014842d480b571495a4a0363793f7367");
}

TEST_F(BoundaryConditionTests, JustOverOneBlock_65_Bytes) {
  std::string input(65, 'a');
  RunTest(input, "c743a45e0d2e6a95cb859adae0248435");
}

class LargeInputTest : public ::testing::Test {
 protected:
  void SetUp() override {
    temp_filename_ = "md5_large_test_file.tmp";
    std::ofstream outfile(temp_filename_, std::ios::binary);
    if (!outfile) {
      GTEST_FAIL() << "Failed to create temporary file for testing.";
    }

    // Write 10 MiB of data.
    constexpr std::size_t k_file_size = 10 * 1024 * 1024;
    constexpr char k_char_to_write = 'M';
    std::vector<char> buffer(4096, k_char_to_write);

    for (std::size_t bytes_written = 0; bytes_written < k_file_size;
         bytes_written += buffer.size()) {
      outfile.write(buffer.data(), buffer.size());
    }
  }

  void TearDown() override { std::remove(temp_filename_.c_str()); }

  std::string temp_filename_;
};

TEST_F(LargeInputTest, StreamMatchesMemoryForLargeFile) {
  const std::string expected_hash = "7599a0f48ceb8311543fb7d7c4dc9235";

  std::ifstream infile(temp_filename_, std::ios::binary);
  ASSERT_TRUE(infile.is_open()) << "Failed to open temporary file for reading.";

  const std::string stream_hash = md5_lib::calculate_md5(infile);

  EXPECT_EQ(stream_hash, expected_hash);
}