#pragma once
#include "ff.hpp"
#include <iomanip>
#include <random>
#include <sstream>
#include <string_view>
#include <type_traits>

// Fill memory allocation with `len` -many random elements of unsigned integral
// type T, uniformly sampled from [0, 2 ^ bit_width(T)), using Mersenne Twister
// engine, which is seeded with system randomness.
//
// I strongly suggest you read
// https://en.cppreference.com/w/cpp/numeric/random/random_device before using
// this routine, just to be sure that you're using it in right way in right
// context.
template<typename T>
inline void
random_fill(T* const data, const size_t len)
  requires(std::is_unsigned_v<T>)
{
  std::random_device rd;
  std::mt19937_64 gen(rd());
  std::uniform_int_distribution<T> dis{};

  for (size_t i = 0; i < len; i++) {
    data[i] = dis(gen);
  }
}

// Converts a byte array into hex string; see
// https://stackoverflow.com/a/14051107
inline const std::string
to_hex(const uint8_t* const bytes, const size_t len)
{
  std::stringstream ss;
  ss << std::hex;

  for (size_t i = 0; i < len; i++) {
    ss << std::setw(2) << std::setfill('0') << static_cast<uint32_t>(bytes[i]);
  }
  return ss.str();
}

// Given a hex encoded string, this routine computes a byte array of length
// `hex_string.length() / 2` -bytes; see https://stackoverflow.com/a/30606613
inline void
to_byte_array(const std::string& hex_string, uint8_t* const __restrict bytes)
{
  const size_t slen = hex_string.length();
  const size_t blen = slen / 2;

  for (size_t i = 0; i < blen; i++) {
    const size_t off = i * 2;

    const auto t0 = hex_string.substr(off, 2);
    const auto t1 = std::strtol(t0.c_str(), nullptr, 16);
    const auto t2 = static_cast<uint8_t>(t1);

    bytes[i] = t2;
  }
}

// Computes binary logarithm of `n`, when n is power of 2
inline size_t
bin_log(size_t n)
{
  size_t cnt = 0ul;

  while (n > 1ul) {
    cnt++;
    n >>= 1;
  }

  return cnt;
}
