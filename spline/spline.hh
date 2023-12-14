// Dedicated to the Public Domain under the Unlicense: https://unlicense.org/UNLICENSE

#ifndef __SPLINE_HH__
#define __SPLINE_HH__

#include <vector>
#include <cmath>
#include <cassert>

namespace scl {

/** Yield second derivative (Y'') for the spline knots (X,Y)
 * With `DIV6=true`, an internal multiplication by 6.0 is omitted (changes the values),
 * which allowes to save a division by 6.0 in `spline_eval<DIV6=true>()`.
 */
template<typename Sigma, bool DIV6 = false, typename DFloat = long double, typename XFloat, typename YFloat> static inline std::vector<Sigma>
spline_2nd_derivative (const std::vector<XFloat> &xs, const std::vector<YFloat> &ys, const double start_deriv = 1e30, const double end_deriv = 1e30)
{
  assert (xs.size() > 1 && xs.size() <= ys.size());
  constexpr DFloat c6 = DIV6 ? 1.0 : 6.0;                               // spare one mult with spline_eval<DIV6=true>
  const int npoints = xs.size();
  std::vector<Sigma> sg (npoints);
  std::vector<DFloat> b (npoints);
  const int nm1 = npoints - 1;

  // handle the start derivative
  DFloat last_dx = xs[1] - xs[0];
  if (start_deriv > .99e30) {
    b[0] = 0;
    sg[0] = 0;
  } else {
    DFloat new_dj = (ys[1] - ys[0]) / last_dx;
    b[0] = 0.5;
    sg[0] = c6 / 2. * (new_dj - start_deriv) / last_dx;
  }

  // tri-diagonal system and forward substitution
  for (int i = 1; i < nm1; i++) {
    const DFloat delta_x = xs[i + 1] - xs[i];
    if (!(delta_x > 0)) {
      // throw std::runtime_error ("Control point x values must be increasing: i=" + std::to_string (i) + " x[i]=" + std::to_string (xs[i]) + " x[i+1]=" + std::to_string (xs[i+1]));
      assert (delta_x > 0);
    }
    const DFloat x2dx = 2 * (xs[i + 1] - xs[i - 1]);	                // == Forsythe:DO10:B(I)
    const DFloat d1y0 = ys[i] - ys[i - 1];
    const DFloat d1y1 = ys[i + 1] - ys[i];
    const DFloat d2ydx = d1y1 / delta_x - d1y0 / last_dx;	        // == Forsythe:DO10:C(I)
    const DFloat b20 = x2dx - last_dx * b[i - 1];		        // == Forsythe:DO20:B(I)
    b[i] = delta_x / b20;				                // == Forsythe:DO20:D(I)/B(I)
    sg[i] = (c6 * d2ydx - last_dx * sg[i - 1]) / b20;	                // == Forsythe:DO20:C(I)
    last_dx = delta_x;
  }

  // handle the end derivative
  b[nm1] = 0;
  if (end_deriv > .99e30) {
    sg[nm1] = 0;
  } else {
    const DFloat x2dx = 2. * last_dx;
    const DFloat d1y0 = ys[nm1] - ys[nm1 - 1];
    const DFloat d2ydx = end_deriv - d1y0 / last_dx;
    const DFloat b20 = x2dx - last_dx * b[nm1 - 1];
    sg[nm1] = (c6 * d2ydx - last_dx * sg[nm1 - 1]) / b20;
  }

  // backward substitution for coefficient calculation
  for (int i = nm1 - 1; i >= 0; i--)
    sg[i] = sg[i] - b[i] * sg[i + 1];			                // == Forsythe:DO30:C(I) == Forsythe:SIGMA

  // yield second derivative
  return sg;
}

/** Evaluate spline from knot and second derivative series (X[], Y[], Y''[])
 * With `DIV6=true`, a multiplication by 1.0/6.0 can be omitted for derivative values that
 * were calculated with `spline_2nd_derivative<DIV6=true>()`. If `t` falls outside the Spline
 * range, boundary values are returned.
 */
template<typename Sigma, bool DIV6 = false, typename DFloat = long double, typename XFloat, typename YFloat> static inline DFloat
spline_eval (Sigma t, const std::vector<XFloat> &xs, const std::vector<YFloat> &ys, const std::vector<Sigma> &sg) noexcept
{
  // Benchmarks for spline evaluation variants can be found in
  // 2020, "Fast Cubic Spline Interpolation", Haysn Hornbeck, https://arxiv.org/pdf/2001.09253.pdf
  const auto newint = [] (DFloat x, DFloat x0, DFloat x1, DFloat y0, DFloat y1, DFloat sg0, DFloat sg1) noexcept {
    constexpr DFloat div6 = DIV6 ? 1.0 : 1.0 / 6.0;                     // allowes to save one multiplication
    const DFloat h = (x1 - x0);
    const DFloat wh = (x - x0);
    const DFloat inv_h = 1. / h;
    const DFloat bx = (x1 - x);
    const DFloat h2 = h * h;			                        // 3 adds, 1 mult, 1 div
    const DFloat lower = wh * y1 + bx * y0;
    const DFloat C = (wh * wh - h2) * wh * sg1;
    const DFloat D = (bx * bx - h2) * bx * sg0;                         // 1 add, 2 subs, 8 mults
    return (lower + div6 * (C + D)) * inv_h;                            // 2 adds, 2 mult = 19 ops + 1 div
  };
  unsigned l = 0, h = xs.size() - 2;
  if (t >= xs[h])                                                       // right side out of bounds
    return newint (t, xs[h], xs[h+1], ys[h], ys[h+1], sg[h], sg[h+1]);
  while (l < h) {
    const unsigned m = (l + h) / 2;
    if (t < xs[m])
      h = m;
    else if (t >= xs[m+1])
      l = m+1;
    else /* xs[m] <= t < xs[m+1] */
      return newint (t, xs[m], xs[m+1], ys[m], ys[m+1], sg[m], sg[m+1]);
  }
  return ys[0];                                                         // left side out of bounds
}

/// CubicSpline - Spline approximation of a funciton given a number of knots
template<typename Float>
struct CubicSpline {
  std::vector<Float> cpx, cpy, sg;                                      // control points (x, y) and spline coefficients
  CubicSpline() = default;
  template<typename XFloat, typename YFloat>
  /*ctor*/ CubicSpline (const std::vector<XFloat> &xs, const std::vector<YFloat> &ys, double dydx0 = 1e30, double dydx1 = 1e30) { setup (xs, ys, dydx0, dydx1); }
  template<typename FloatLike>
  /*ctor*/ CubicSpline (const std::vector<std::pair<FloatLike,FloatLike>> &xy, double dydx0 = 1e30, double dydx1 = 1e30) { setup (xy, dydx0, dydx1); }
  double   xmin        () const noexcept { return cpx[0]; }
  double   xmax        () const noexcept { return cpx.back(); }
  double   splint      (double t) const noexcept { return spline_eval<Float,true> (t, cpx, cpy, sg); }
  double   operator()  (double t) const noexcept { return splint (t); }
  void
  reset ()
  {
    cpx.clear();
    cpy.clear();
    sg.clear();
  }
  template<typename FloatLike> void
  setup (const std::vector<std::pair<FloatLike,FloatLike>> &xy, double dydx0 = 1e30, double dydx1 = 1e30)
  {
    std::vector<FloatLike> xs (xy.size()), ys (xy.size());
    for (size_t i = 0; i < xy.size(); i++) {
      xs[i] = xy[i].first;
      ys[i] = xy[i].second;
    }
    setup (xs, ys, dydx0, dydx1);
  }
  template<typename XFloat, typename YFloat> void
  setup (const std::vector<XFloat> &xs, const std::vector<YFloat> &ys, double dydx0 = 1e30, double dydx1 = 1e30)
  {
    cpx.clear();
    cpx.assign (xs.begin(), xs.end());
    cpy.clear();
    cpy.assign (ys.begin(), ys.end());
    sg = spline_2nd_derivative<Float,true> (xs, ys, dydx0, dydx1);
  }
};

} // scl

#endif // __SPLINE_HH__
