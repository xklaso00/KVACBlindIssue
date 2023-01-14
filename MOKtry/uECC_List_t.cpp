#include <uECC_List_t.hpp>

uECC_Element_t::uECC_Element_t(uECC_word_t *source, wordcount_t num_words)
{
    wordcount = num_words;
    content = source;
}

uECC_List_t::uECC_List_t(uECC_Element_t *node)
{
    first = node;
    length = 1;
}

void uECC_List_t::add(uECC_Element_t *node)
{
    uECC_Element_t *current = first;
    if (length == 1)
    {
        current->next = node;
    }
    else
    {
        for (int i = 0; i < length - 1; i++)
            current = current->next;

        current->next = node;
    }

    length++;
}

uECC_Element_t *uECC_List_t::get(int index)
{
    uECC_Element_t *current = first;

    for (int i = 0; i < index; i++)
        current = current->next;

    return current;
}

void uECC_List_t::remove(int index)
{
    uECC_Element_t *current = first;
    uECC_Element_t *newNext = first;

    if (length <= 1 || index == length - 1)
        return;

    if (index == 0)
    {
        first = first->next;
        return;
    }

    for (int i = 0; i < index - 1; i++)
        current = current->next;
    for (int i = 0; i < index + 1; i++)
        newNext = newNext->next;

    current->next = newNext;
    length--;
}