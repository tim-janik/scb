
# Cubic Spline Interpolation Implementation

The header file `spline.hh` contains functions and a `CubicSpline` class, which can be used
to create a spline approximation of a function given a number of knots (control points)
with third-order polynomial segments connecting each pair of data points.
The class provides methods for setting up the spline from control points and evaluating
the spline at a given point.

The code is loosely modeled after the following sources:

1. "Computer methods for mathematical computations" by G. Forsythe et al, 1977, pages 76-79, functions `spline()` and `seval()`
2. "Fast Cubic Spline Interpolation" by Haysn Hornbeck, [arXiv:2001.09253 (2020)](https://arxiv.org/pdf/2001.09253.pdf)

The source code is dedicated to the Public Domain under the [Unlicense](https://unlicense.org/UNLICENSE).
