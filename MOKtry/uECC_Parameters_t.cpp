#include "uECC_Parameters_t.hpp"

uECC_Parameters_t::uECC_Parameters_t(const uECC_Curve_t *fromCurve)
{
    curve = fromCurve;
    n = uECC_curve_n(curve);
    g = uECC_curve_G(curve);
    nativeCount = uECC_curve_num_words(curve);
    nativeNCount = uECC_curve_num_n_words(curve);
    byteCount = uECC_curve_num_bytes(curve);
}