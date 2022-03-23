#pragma once
#include "utils.hpp"
#include <cassert>

namespace test {

void
is_nonzero_coeff(sycl::queue& q, const size_t dim, const size_t wg_size)
{
  const size_t i_size = sizeof(uint32_t) * dim;
  const size_t o_size = sizeof(uint32_t) * 1;

  uint32_t* poly_0 = static_cast<uint32_t*>(sycl::malloc_shared(i_size, q));
  uint32_t* poly_1 = static_cast<uint32_t*>(sycl::malloc_shared(i_size, q));
  uint32_t* nz_acc_0 = static_cast<uint32_t*>(sycl::malloc_shared(o_size, q));
  uint32_t* nz_acc_1 = static_cast<uint32_t*>(sycl::malloc_shared(o_size, q));

  random_fill(poly_0, dim);
  random_fill(poly_1, dim);

  // explicitly putting zero, as `random_fill` won't do that
  poly_1[dim >> 1] = 0u;

  using evt = sycl::event;

  // initializing to `true` value is required !
  evt evt0 = q.single_task([=]() {
    *nz_acc_0 = 1u;
    *nz_acc_1 = 1u;
  });
  // must yield true
  evt evt1 =
    utils::is_nonzero_coeff(q, poly_0, dim, wg_size, nz_acc_0, { evt0 });
  // must yield false
  evt evt2 =
    utils::is_nonzero_coeff(q, poly_1, dim, wg_size, nz_acc_1, { evt0 });

  q.ext_oneapi_submit_barrier({ evt1, evt2 }).wait();

  bool nz_host_0 = true;
  bool nz_host_1 = true;
  for (size_t i = 0; i < dim; i++) {
    nz_host_0 &= (poly_0[i] != 0);
    nz_host_1 &= (poly_1[i] != 0);
  }

  assert((bool)nz_acc_0[0] && (bool)nz_acc_0[0] == nz_host_0);
  assert(!(bool)nz_acc_1[0] && (bool)nz_acc_1[0] == nz_host_1);

  sycl::free(poly_0, q);
  sycl::free(poly_1, q);
  sycl::free(nz_acc_0, q);
  sycl::free(nz_acc_1, q);
}

}
