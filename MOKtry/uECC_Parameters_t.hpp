#ifndef AAA_HEADER
#define AAA_HEADER

#include <uECC_vli.h>

class uECC_Parameters_t
{
public:
    const uECC_Curve_t *curve;
    const uECC_word_t *n;
    const uECC_word_t *g;
    wordcount_t nativeCount;
    wordcount_t nativeNCount;
    wordcount_t byteCount;

    uECC_Parameters_t(const uECC_Curve_t * fromCurve);
};
#endif