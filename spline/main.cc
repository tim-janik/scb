// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

#include "spline.hh"

#include <cstdio>
#include <cstring>

static void
cubic_spline_test()
{
  using namespace scl;
  std::vector<double> xs, ys;
  // 3 period sine, assert close approximation
  size_t n = 3 * 8 + 1;
  for (size_t i = 0; i < n; i++) {
    xs.push_back (i * 2 * M_PI/8);
    ys.push_back (sin (xs.back()));
  }
  // check approximation delta
  {
    CubicSpline<double> cs (xs, ys, 1, 1);
    for (double d = 0; d <= 3 * 2 * M_PI + 1e-9; d += 0.1) {
      const double iy = cs.splint (d), ry = sin (d), err = fabs (iy - ry);
      // printf ("%g %g # %g\n", d, cs.splint (d), err); // gnuplot coords
      assert (err < 0.002);
    }
  }
  printf ("  OK    CubicSpline approximating sin()\n");
}

int
main (int argc, const char *argv[])
{
  for (int i = 1; i < argc; i++)
    if (0 == strcasecmp (argv[i], "--check")) {
      cubic_spline_test();
      return 0;
    }
  printf ("Usage: %s --check\n", argv[0]);
  return 0;
}
// clang++ -std=gnu++17 -Wall -march=native -O3 main.cc -o spline && ./spline --check
