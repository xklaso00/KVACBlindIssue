#include <types.hpp>

#define ISSUED 10
#define REVEALED 2

void hash(const uint8_t *data, wordcount_t length, uint8_t *destination, SHA256 * sha256);
//void hashFromNative(uECC_word_t *source, wordcount_t num_words, wordcount_t byte_count, uint8_t *destination);
void hashUpdate(uECC_word_t *source, wordcount_t num_words, wordcount_t byte_count, SHA256 *sha256);

void fillWithRandoms(uECC_List_t *list, uECC_Parameters_t *parameters);

void issue(uECC_Parameters_t *parameters, uECC_List_t * m_list, uECC_List_t * x_list, uECC_word_t *sigma, uECC_List_t *sigma_list);
void SignGFirstHalf(uECC_List_t* x_list, uECC_List_t* m_list, uECC_Parameters_t* parameters, uECC_word_t* sum);
void SignGSecondHalf(uECC_List_t* x_list, uECC_List_t* m_list, uECC_Parameters_t* parameters, uECC_word_t* targetSigma, uECC_word_t* sum);
void signSigma(uECC_word_t* sigma, uECC_List_t* x_list, uECC_Parameters_t* parameters, uECC_List_t* target_sigma_list);
void issueModified(uECC_Parameters_t* parameters, uECC_List_t* m_list, uECC_List_t* x_list, uECC_word_t* sigma, uECC_List_t* sigma_list, uECC_word_t* client_private);
void declare(uECC_Parameters_t *parameters, uECC_word_t *nonce, uECC_word_t *sigma, uECC_List_t *sigma_list, uECC_List_t *m_list, uECC_word_t *sigma_A, uECC_word_t *e, uECC_word_t *s_r, uECC_List_t *s_m_list);
void declareModified(uECC_Parameters_t* parameters, uECC_word_t* nonce, uECC_word_t* sigma, uECC_List_t* sigma_list, uECC_List_t* m_list, uECC_word_t* sigma_A, uECC_word_t* e, uECC_word_t* s_r, uECC_List_t* s_m_list, uECC_word_t* client_private, uECC_word_t* S_k);
bool verifyModified(uECC_Parameters_t* parameters, uECC_word_t* e, uECC_word_t* nonce, uECC_List_t* s_m_list, uECC_word_t* s_r, uECC_word_t* sigma_A, uECC_List_t* x_list, uECC_List_t* m_list, uECC_word_t* S_k);
bool verify(uECC_Parameters_t *parameters, uECC_word_t *e, uECC_word_t *nonce, uECC_List_t *s_m_list, uECC_word_t *s_r, uECC_word_t *sigma_A, uECC_List_t * x_list, uECC_List_t * m_list);