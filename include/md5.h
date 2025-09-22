#ifndef MD5_LIB_INCLUDE_MD5_H_
#define MD5_LIB_INCLUDE_MD5_H_

#include <istream>
#include <string>

namespace md5_lib {

/**
 * @brief Calculates the MD5 hash of a data stream.
 *
 * Reads the input stream in chunks. The stream's state will be modified
 * by the read operations.
 *
 * @param stream The input stream to hash. The stream will be read until EOF.
 * @return A 32-character lowercase hexadecimal string representing the MD5
 * hash.
 * @throw std::ios_base::failure on stream reading errors if the stream's
 *        exception mask is set to throw on `badbit`.
 */
[[nodiscard]] std::string CalculateMD5(std::istream& stream);

/**
 * @brief Calculates the MD5 hash of a contiguous block of memory.
 *
 * A convenience overload for hashing data that is already in memory, such as
 * a std::string or std::vector's data.
 *
 * @param data A non-null pointer to the beginning of the data block.
 *             The type is `const unsigned char*` as it is the conventional
 *             type in C++ for representing raw, untyped byte data.
 * @param size The size of the data block in bytes.
 * @return A 32-character lowercase hexadecimal string representing the MD5
 * hash.
 */
[[nodiscard]] std::string CalculateMD5(const unsigned char* data,
                                       std::size_t size);

}  // namespace md5_lib

#endif  // MD5_LIB_INCLUDE_MD5_H_