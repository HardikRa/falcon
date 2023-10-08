#include "falcon.hpp"
#include <iostream>

int main() {
  constexpr size_t N = 512;
  uint8_t pkey[falcon::encoding::PKEY_SIZE(N)];
  uint8_t skey[falcon::encoding::SKEY_SIZE(N)];
  uint8_t msg[] = "Hello, world!";
  uint8_t sig[falcon::signing::SIGNATURE_SIZE(N)];

  falcon::keygen<N>(pkey, skey);
  falcon::sign<N>(skey, msg, sizeof(msg), sig);
  const bool verified = falcon::verify<N>(pkey, msg, sizeof(msg), sig);

  if (verified) {
    std::cout << "Signature verified successfully!\n";
  } else {
    std::cout << "Signature verification failed.\n";
  }

  return 0;
}