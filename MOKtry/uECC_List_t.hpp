
#ifndef REE_HEADER
#define REE_HEADER
#include <uECC_vli.h>


class uECC_Element_t
{
public:
    uECC_word_t *content;
    wordcount_t wordcount;
    uECC_Element_t *next;

    uECC_Element_t(uECC_word_t *source, wordcount_t num_words);
};

class uECC_List_t
{
public:
    uECC_Element_t *first;
    int length;

    uECC_List_t(uECC_Element_t *node);

    void add(uECC_Element_t *node);
    uECC_Element_t *get(int index);
    void remove(int index);
};
#endif
