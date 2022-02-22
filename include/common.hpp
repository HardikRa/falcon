#pragma once
#include "ff.hpp"
#include <random>

// Fill host accessible memory allocation with `dim` -many
// random integers, uniformly chosen from [-3, 4]
void
random_fill(double* const data, const size_t dim)
{
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<long> dis(-3., 4.);

  for (size_t i = 0; i < dim; i++) {
    data[i] = static_cast<double>(dis(gen));
  }
}

// Fill host accessible memory allocation with `dim` -many
// random prime field elements, uniformly chosen from [1, 12289)
void
random_fill(uint32_t* const data, const size_t dim)
{
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<uint32_t> dis(1, ff::Q - 1);

  for (size_t i = 0; i < dim; i++) {
    data[i] = dis(gen);
  }
}
