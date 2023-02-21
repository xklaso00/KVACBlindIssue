#include <wbb.hpp>
#include <stdio.h>
#include <vcruntime_string.h>
#include<MOKtry.cpp>
static void printArray(const uECC_word_t *content, wordcount_t byteCount, bool newLine)
{
    uint8_t *output = new uint8_t[byteCount]();
    uECC_vli_nativeToBytes(output, byteCount, content);

    int i;
    for (i = 0; i < byteCount; i++)
    {
        //Serial.print(output[i]);
        //Serial.print(" ");
    }

    //if (newLine)
        //Serial.println();
}

void hash(const uint8_t *data, wordcount_t length, uint8_t *destination, SHA256 *sha256)
{
    int i;
    //sha256->reset();

    for (i = 0; i < length / 2; i++)
        sha256->update(data + i * 2, 2);

    //sha256->finalize(destination, HASH_SIZE);
   // sha256->clear();
    destination = sha256->digest();
}

void hashFromNative(uECC_word_t *source, wordcount_t num_words, wordcount_t byte_count, uint8_t *destination, SHA256 *sha256)
{
    uint8_t *byteForm = new uint8_t[byte_count]();

    uECC_vli_nativeToBytes(byteForm, byte_count, source);
    hash(byteForm, byte_count, destination, sha256);
}

void hashUpdate(uECC_word_t *source, wordcount_t num_words, wordcount_t byte_count, SHA256 *sha256)
{
    uint8_t *byteForm = new uint8_t[byte_count]();
    int i;

    uECC_vli_nativeToBytes(byteForm, byte_count, source);
    for (i = 0; i < byte_count / 2; i++)
        sha256->update(byteForm + i * 2, 2);
}

void fillWithRandoms(uECC_List_t *list, uECC_Parameters_t *parameters)
{
    for (int i = 0; i < list->length; i++)
        uECC_generate_random_int(list->get(i)->content, parameters->n, list->get(i)->wordcount);
}

//COMPUTATION OF SIGMA
void signG(uECC_List_t *x_list, uECC_List_t *m_list, uECC_Parameters_t *parameters, uECC_word_t *targetSigma)
{
    uECC_word_t *sum = new uECC_word_t[parameters->nativeNCount]();

    for (int i = 0; i < ISSUED; i++)
    {
        uECC_word_t *mul_x_m = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(mul_x_m, m_list->get(i)->content, x_list->get(i + 1)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modAdd(sum, sum, mul_x_m, parameters->n, parameters->nativeNCount);
    }

    uECC_vli_modAdd(sum, sum, x_list->get(0)->content, parameters->n, parameters->nativeNCount);
    uECC_vli_modInv(sum, sum, parameters->n, parameters->nativeNCount);
    uECC_point_mult(targetSigma, parameters->g, sum, parameters->curve);
}

void signGModified(uECC_List_t* x_list, uECC_List_t* m_list, uECC_Parameters_t* parameters, uECC_word_t* targetSigma, uECC_word_t* client_private)
{
    uECC_word_t* sum = new uECC_word_t[parameters->nativeNCount]();

    for (int i = 0; i < ISSUED; i++)
    {
        uECC_word_t* mul_x_m = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(mul_x_m, m_list->get(i)->content, x_list->get(i + 1)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modAdd(sum, sum, mul_x_m, parameters->n, parameters->nativeNCount);
    }

    uECC_vli_modAdd(sum, sum, x_list->get(0)->content, parameters->n, parameters->nativeNCount);
    //this I modded
    const wordcount_t byteCount = uECC_curve_num_bytes(parameters->curve);
    const uECC_word_t* n = uECC_curve_n(parameters->curve);
    uECC_Curve nowCurve = parameters->curve;
    
    uint8_t* gotBack;
    if (nowCurve == uECC_secp160r1()) {
        uint8_t nBytes[20];
        uECC_vli_nativeToBytes(nBytes, byteCount, n);
        /*uint8_t* man_Sec = new uint8_t[byteCount]();
        uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
        uint8_t* client_Sec = new uint8_t[byteCount]();
        uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
        tutu(nBytes, man_Sec, client_Sec, 20);*/
        uint8_t man_Sec[20];
        uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
        uint8_t client_Sec [20];
        uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
        gotBack=tutu(nBytes, man_Sec, client_Sec, 20,NULL, nowCurve);

    }
    else if(nowCurve == uECC_secp192r1()) {
        
        uint8_t nBytes[24];
        uECC_vli_nativeToBytes(nBytes, byteCount, n);
        uint8_t man_Sec[24];
        uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
        uint8_t client_Sec[24];
        uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
        gotBack = tutu(nBytes, man_Sec, client_Sec, 24, NULL, nowCurve);
    }
    else if (nowCurve == uECC_secp224r1()) {
        
        uint8_t nBytes[28];
        uECC_vli_nativeToBytes(nBytes, byteCount, n);
        uint8_t man_Sec[28];
        uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
        uint8_t client_Sec[28];
        uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
        gotBack = tutu(nBytes, man_Sec, client_Sec, 28, NULL, nowCurve);
    }
    else {
        uint8_t nBytes[32];
        uECC_vli_nativeToBytes(nBytes, byteCount, n);
        uint8_t man_Sec[32];
        uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
        uint8_t client_Sec[32];
        uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
        gotBack = tutu(nBytes, man_Sec, client_Sec, 32, NULL, nowCurve);
    }


    //int sizee = 20;
    //uint8_t nBytes[32];
    

    uECC_vli_modAdd(sum, sum, client_private, parameters->n, parameters->nativeNCount);
    //multiMOD
    uECC_word_t* compareMe = new uECC_word_t[parameters->nativeNCount]();
    uECC_vli_bytesToNative(compareMe, gotBack, byteCount);
    int same=uECC_vli_cmp(compareMe, sum, parameters->nativeNCount);
    printf(" is it same %d \n",same);
    uECC_vli_set(sum, compareMe, parameters->nativeNCount);


    uECC_vli_modInv(sum, sum, parameters->n, parameters->nativeNCount);
    uECC_point_mult(targetSigma, parameters->g, sum, parameters->curve);
}

void SignGFirstHalf(uECC_List_t* x_list, uECC_List_t* m_list, uECC_Parameters_t* parameters, uECC_word_t* sum) {
    //uECC_word_t* sum = new uECC_word_t[parameters->nativeNCount]();

    for (int i = 0; i < ISSUED; i++)
    {
        uECC_word_t* mul_x_m = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(mul_x_m, m_list->get(i)->content, x_list->get(i + 1)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modAdd(sum, sum, mul_x_m, parameters->n, parameters->nativeNCount);
    }

    uECC_vli_modAdd(sum, sum, x_list->get(0)->content, parameters->n, parameters->nativeNCount);
}

void SignGSecondHalf(uECC_List_t* x_list, uECC_List_t* m_list, uECC_Parameters_t* parameters, uECC_word_t* targetSigma, uECC_word_t* sum) {
    uECC_vli_modInv(sum, sum, parameters->n, parameters->nativeNCount);
    uECC_point_mult(targetSigma, parameters->g, sum, parameters->curve);
}

//COMPUTATION OF SIGMAS FOR EACH X
void signSigma(uECC_word_t *sigma, uECC_List_t *x_list, uECC_Parameters_t *parameters, uECC_List_t *target_sigma_list)
{
    for (int i = 0; i < ISSUED; i++)
        uECC_point_mult(target_sigma_list->get(i)->content, sigma, x_list->get(i + 1)->content, parameters->curve);
}

void issue(uECC_Parameters_t *parameters, uECC_List_t *m_list, uECC_List_t *x_list, uECC_word_t *sigma, uECC_List_t *sigma_list)
{
    signG(x_list, m_list, parameters, sigma);
    signSigma(sigma, x_list, parameters, sigma_list);
}
void issueModified(uECC_Parameters_t* parameters, uECC_List_t* m_list, uECC_List_t* x_list, uECC_word_t* sigma, uECC_List_t* sigma_list, uECC_word_t* client_private)
{
    signGModified(x_list, m_list, parameters, sigma,client_private);
    signSigma(sigma, x_list, parameters, sigma_list);
}

void declare(uECC_Parameters_t *parameters, uECC_word_t *nonce, uECC_word_t *sigma, uECC_List_t *sigma_list, uECC_List_t *m_list, uECC_word_t *sigma_A, uECC_word_t *e, uECC_word_t *s_r, uECC_List_t *s_m_list)
{
    uECC_word_t *dummy_ro_m1 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m2 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m3 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m4 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m5 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m6 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m7 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m8 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m9 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *dummy_ro_m10 = new uECC_word_t[parameters->nativeNCount]();
    uECC_Element_t dummy_ro_m1_el(dummy_ro_m1, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m2_el(dummy_ro_m2, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m3_el(dummy_ro_m3, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m4_el(dummy_ro_m4, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m5_el(dummy_ro_m5, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m6_el(dummy_ro_m6, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m7_el(dummy_ro_m7, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m8_el(dummy_ro_m8, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m9_el(dummy_ro_m9, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m10_el(dummy_ro_m10, parameters->nativeNCount);

    uECC_word_t *r = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *ro_r = new uECC_word_t[parameters->nativeNCount]();
    uECC_generate_random_int(r, parameters->n, parameters->nativeNCount);
    uECC_generate_random_int(ro_r, parameters->n, parameters->nativeNCount);
    uECC_point_mult(sigma_A, sigma, r, parameters->curve);
    uECC_List_t ro_m_list(&dummy_ro_m1_el);



    ro_m_list.add(&dummy_ro_m2_el);
    ro_m_list.add(&dummy_ro_m3_el);
    ro_m_list.add(&dummy_ro_m4_el);
    ro_m_list.add(&dummy_ro_m5_el);
    ro_m_list.add(&dummy_ro_m6_el);
    ro_m_list.add(&dummy_ro_m7_el);
    ro_m_list.add(&dummy_ro_m8_el);
    ro_m_list.add(&dummy_ro_m9_el);
    ro_m_list.add(&dummy_ro_m10_el);

    ro_m_list.length = ISSUED;
    //createAndFillWithRandoms(&ro_m_list, parameters, m_list->length, 1);
    fillWithRandoms(&ro_m_list, parameters);

    uECC_word_t *g_ro_r = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t *t = new uECC_word_t[parameters->nativeNCount * 2]();

    uECC_word_t *e_mult_r = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *e_mult_m = new uECC_word_t[parameters->nativeNCount]();

    uECC_word_t *tmp_sigma_sum = new uECC_word_t[parameters->nativeNCount * 2]();
    for (int i = 0; i < ISSUED-REVEALED; i++)
    {
        uECC_word_t *tmp_sigma = new uECC_word_t[parameters->nativeNCount * 2]();
        uECC_word_t *multiplier = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(multiplier, ro_m_list.get(i)->content, r, parameters->n, parameters->nativeNCount);
        uECC_point_mult(tmp_sigma, sigma_list->get(i)->content, multiplier, parameters->curve);

        if (i == 0)
            tmp_sigma_sum = tmp_sigma;
        else
            uECC_point_add(tmp_sigma_sum, tmp_sigma, tmp_sigma_sum, parameters->curve);
    }

    uECC_point_mult(g_ro_r, parameters->g, ro_r, parameters->curve);

    if (ISSUED - REVEALED == 0)
    {
        uECC_vli_set(t, g_ro_r, parameters->nativeNCount * 2);
    }
    else
    {
        uECC_point_add(tmp_sigma_sum, g_ro_r, t, parameters->curve);
    }    

    SHA256 oldHash;
    //oldHash.reset();
    uECC_word_t *resultHash = new uECC_word_t[HASH_SIZE]();
    uint8_t* placeholder = new uint8_t[HASH_SIZE]();
    hashUpdate(sigma_A, parameters->nativeNCount * 2, parameters->byteCount * 2, &oldHash);
    hashUpdate(t, parameters->nativeNCount * 2, parameters->byteCount * 2, &oldHash);
    hashUpdate(nonce, parameters->nativeNCount, parameters->byteCount, &oldHash);
    //oldHash.finalize(resultHash, HASH_SIZE);
    placeholder = oldHash.digest();
    
    uECC_vli_bytesToNative(resultHash, placeholder, HASH_SIZE);
    uECC_vli_mmod(e, resultHash, parameters->n, parameters->nativeNCount);

    uECC_vli_modMult(e_mult_r, e, r, parameters->n, parameters->nativeNCount);
    uECC_vli_modAdd(s_r, ro_r, e_mult_r, parameters->n, parameters->nativeNCount);

    for (int i = 0; i < ISSUED-REVEALED; i++)
    {
        uECC_word_t *e_mult = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(e_mult, e, m_list->get(i)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modSub(s_m_list->get(i)->content, ro_m_list.get(i)->content, e_mult, parameters->n, parameters->nativeNCount);
    }
}

void declareModified(uECC_Parameters_t* parameters, uECC_word_t* nonce, uECC_word_t* sigma, uECC_List_t* sigma_list, uECC_List_t* m_list, uECC_word_t* sigma_A, uECC_word_t* e, uECC_word_t* s_r, uECC_List_t* s_m_list, uECC_word_t* client_private, uECC_word_t* S_k)
{
    uECC_word_t* dummy_ro_m1 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m2 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m3 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m4 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m5 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m6 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m7 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m8 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m9 = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* dummy_ro_m10 = new uECC_word_t[parameters->nativeNCount]();
    uECC_Element_t dummy_ro_m1_el(dummy_ro_m1, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m2_el(dummy_ro_m2, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m3_el(dummy_ro_m3, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m4_el(dummy_ro_m4, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m5_el(dummy_ro_m5, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m6_el(dummy_ro_m6, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m7_el(dummy_ro_m7, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m8_el(dummy_ro_m8, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m9_el(dummy_ro_m9, parameters->nativeNCount);
    uECC_Element_t dummy_ro_m10_el(dummy_ro_m10, parameters->nativeNCount);

    uECC_word_t* r = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* ro_r = new uECC_word_t[parameters->nativeNCount]();
    uECC_generate_random_int(r, parameters->n, parameters->nativeNCount);
    uECC_generate_random_int(ro_r, parameters->n, parameters->nativeNCount);
    uECC_point_mult(sigma_A, sigma, r, parameters->curve);
    uECC_List_t ro_m_list(&dummy_ro_m1_el);
    //new code
    uECC_word_t* ro_k = new uECC_word_t[parameters->nativeNCount]();
    uECC_generate_random_int(ro_k, parameters->n, parameters->nativeNCount);


    ro_m_list.add(&dummy_ro_m2_el);
    ro_m_list.add(&dummy_ro_m3_el);
    ro_m_list.add(&dummy_ro_m4_el);
    ro_m_list.add(&dummy_ro_m5_el);
    ro_m_list.add(&dummy_ro_m6_el);
    ro_m_list.add(&dummy_ro_m7_el);
    ro_m_list.add(&dummy_ro_m8_el);
    ro_m_list.add(&dummy_ro_m9_el);
    ro_m_list.add(&dummy_ro_m10_el);

    ro_m_list.length = ISSUED;
    //createAndFillWithRandoms(&ro_m_list, parameters, m_list->length, 1);
    fillWithRandoms(&ro_m_list, parameters);

    uECC_word_t* g_ro_r = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t* t = new uECC_word_t[parameters->nativeNCount * 2]();

    uECC_word_t* e_mult_r = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* e_mult_m = new uECC_word_t[parameters->nativeNCount]();

    uECC_word_t* tmp_sigma_sum = new uECC_word_t[parameters->nativeNCount * 2]();
    for (int i = 0; i < ISSUED - REVEALED; i++)
    {
        uECC_word_t* tmp_sigma = new uECC_word_t[parameters->nativeNCount * 2]();
        uECC_word_t* multiplier = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(multiplier, ro_m_list.get(i)->content, r, parameters->n, parameters->nativeNCount);
        uECC_point_mult(tmp_sigma, sigma_list->get(i)->content, multiplier, parameters->curve);

        if (i == 0)
            tmp_sigma_sum = tmp_sigma;
        else
            uECC_point_add(tmp_sigma_sum, tmp_sigma, tmp_sigma_sum, parameters->curve);
    }

    uECC_point_mult(g_ro_r, parameters->g, ro_r, parameters->curve);
    //new code
    uECC_word_t* rom_r = new uECC_word_t[parameters->nativeNCount]();
    uECC_vli_modMult(rom_r,ro_k,r,parameters->n,parameters->nativeNCount);
    uECC_word_t* sig_to_rom_r = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_point_mult(sig_to_rom_r, sigma, rom_r, parameters->curve);


    if (ISSUED - REVEALED == 0)
    {
        uECC_vli_set(t, g_ro_r, parameters->nativeNCount * 2); //this might need work later
        uECC_point_add(t, sig_to_rom_r, t, parameters->curve);
    }
    else
    {
        uECC_point_add(tmp_sigma_sum, g_ro_r, t, parameters->curve);
        //uECC_word_t *tmp_t = new uECC_word_t(parameters->nativeNCount * 2);
        uECC_point_add(t, sig_to_rom_r, t, parameters->curve);
    }

    SHA256 oldHash;
    //oldHash.reset();
    uECC_word_t* resultHash = new uECC_word_t[HASH_SIZE]();
    uint8_t* placeholder = new uint8_t[HASH_SIZE]();
    hashUpdate(sigma_A, parameters->nativeNCount * 2, parameters->byteCount * 2, &oldHash);
    hashUpdate(t, parameters->nativeNCount * 2, parameters->byteCount * 2, &oldHash);
    hashUpdate(nonce, parameters->nativeNCount, parameters->byteCount, &oldHash);
    //oldHash.finalize(resultHash, HASH_SIZE);
    placeholder = oldHash.digest();

    uECC_vli_bytesToNative(resultHash, placeholder, HASH_SIZE);
    uECC_vli_mmod(e, resultHash, parameters->n, parameters->nativeNCount);

    uECC_vli_modMult(e_mult_r, e, r, parameters->n, parameters->nativeNCount);
    uECC_vli_modAdd(s_r, ro_r, e_mult_r, parameters->n, parameters->nativeNCount);

    for (int i = 0; i < ISSUED - REVEALED; i++)
    {
        uECC_word_t* e_mult = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(e_mult, e, m_list->get(i)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modSub(s_m_list->get(i)->content, ro_m_list.get(i)->content, e_mult, parameters->n, parameters->nativeNCount);
    }

    //new code here
    uECC_word_t* e_sk_u= new uECC_word_t[parameters->nativeNCount]();
    uECC_vli_modMult(e_sk_u,e,client_private,parameters->n,parameters->nativeNCount);
    uECC_vli_modSub(S_k, ro_k, e_sk_u, parameters->n, parameters->nativeNCount);
}

bool verify(uECC_Parameters_t *parameters, uECC_word_t *e, uECC_word_t *nonce, uECC_List_t *s_m_list, uECC_word_t *s_r, uECC_word_t *sigma_A, uECC_List_t *x_list, uECC_List_t *m_list)
{
    uECC_word_t *t_new = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t *g_s_r = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t *sigma_A_mult = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t *e_mult_x0 = new uECC_word_t[parameters->nativeNCount]();

    uECC_word_t *tmp_sum = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t *tmp_sum_2 = new uECC_word_t[parameters->nativeNCount]();
    int i = 0;
    for (; i < ISSUED - REVEALED; i++)
    {
        uECC_word_t *tmp_mul = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(tmp_mul, s_m_list->get(i)->content, x_list->get(i + 1)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modAdd(tmp_sum, tmp_sum, tmp_mul, parameters->n, parameters->nativeNCount);
    }

    for (; i < ISSUED; i++)
    {
        uECC_word_t *tmp_mul = new uECC_word_t[parameters->nativeNCount]();
        uECC_word_t *tmp_mul_2 = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(tmp_mul, m_list->get(i)->content, x_list->get(i + 1)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modMult(tmp_mul_2, tmp_mul, e, parameters->n, parameters->nativeNCount);

        uECC_vli_modAdd(tmp_sum_2, tmp_sum_2, tmp_mul_2, parameters->n, parameters->nativeNCount);
    }

    uECC_vli_modMult(e_mult_x0, e, x_list->get(0)->content, parameters->n, parameters->nativeNCount);
    uECC_vli_modSub(tmp_sum, tmp_sum, e_mult_x0, parameters->n, parameters->nativeNCount);
    uECC_vli_modSub(tmp_sum, tmp_sum, tmp_sum_2, parameters->n, parameters->nativeNCount);

    uECC_point_mult(g_s_r, parameters->g, s_r, parameters->curve);
    uECC_point_mult(sigma_A_mult, sigma_A, tmp_sum, parameters->curve);

    uECC_point_add(g_s_r, sigma_A_mult, t_new, parameters->curve);

    SHA256 newHash;
    //newHash.reset();
    uECC_word_t *resultHash_new = new uECC_word_t[HASH_SIZE]();
    hashUpdate(sigma_A, parameters->nativeNCount * 2, parameters->byteCount * 2, &newHash);
    hashUpdate(t_new, parameters->nativeNCount * 2, parameters->byteCount * 2, &newHash);
    hashUpdate(nonce, parameters->nativeNCount, parameters->byteCount, &newHash);
    //newHash.finalize(resultHash_new, HASH_SIZE);
    uint8_t* placeholder2 = new uint8_t[HASH_SIZE]();

    placeholder2=newHash.digest();
    uECC_vli_bytesToNative(resultHash_new, placeholder2, HASH_SIZE);

    uECC_word_t *e_new = new uECC_word_t[parameters->nativeNCount]();
    //uECC_vli_bytesToNative(e_new, resultHash_new, byteCount);
    uECC_vli_mmod(e_new, resultHash_new, parameters->n, parameters->nativeNCount);

    return 0 == memcmp(e, e_new, parameters->nativeNCount);
}
bool verifyModified(uECC_Parameters_t* parameters, uECC_word_t* e, uECC_word_t* nonce, uECC_List_t* s_m_list, uECC_word_t* s_r, uECC_word_t* sigma_A, uECC_List_t* x_list, uECC_List_t* m_list, uECC_word_t *S_k)
{
    uECC_word_t* t_new = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t* g_s_r = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t* sigma_A_mult = new uECC_word_t[parameters->nativeNCount * 2]();
    uECC_word_t* e_mult_x0 = new uECC_word_t[parameters->nativeNCount]();

    uECC_word_t* tmp_sum = new uECC_word_t[parameters->nativeNCount]();
    uECC_word_t* tmp_sum_2 = new uECC_word_t[parameters->nativeNCount]();
    int i = 0;
    for (; i < ISSUED - REVEALED; i++)
    {
        uECC_word_t* tmp_mul = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(tmp_mul, s_m_list->get(i)->content, x_list->get(i + 1)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modAdd(tmp_sum, tmp_sum, tmp_mul, parameters->n, parameters->nativeNCount);
    }

    for (; i < ISSUED; i++)
    {
        uECC_word_t* tmp_mul = new uECC_word_t[parameters->nativeNCount]();
        uECC_word_t* tmp_mul_2 = new uECC_word_t[parameters->nativeNCount]();
        uECC_vli_modMult(tmp_mul, m_list->get(i)->content, x_list->get(i + 1)->content, parameters->n, parameters->nativeNCount);
        uECC_vli_modMult(tmp_mul_2, tmp_mul, e, parameters->n, parameters->nativeNCount);

        uECC_vli_modAdd(tmp_sum_2, tmp_sum_2, tmp_mul_2, parameters->n, parameters->nativeNCount);
    }

    uECC_vli_modMult(e_mult_x0, e, x_list->get(0)->content, parameters->n, parameters->nativeNCount);
    uECC_vli_modSub(tmp_sum, tmp_sum, e_mult_x0, parameters->n, parameters->nativeNCount);
    uECC_vli_modSub(tmp_sum, tmp_sum, tmp_sum_2, parameters->n, parameters->nativeNCount);
    //newCode
    uECC_vli_modAdd(tmp_sum,tmp_sum,S_k, parameters->n, parameters->nativeNCount);

    uECC_point_mult(g_s_r, parameters->g, s_r, parameters->curve);
    uECC_point_mult(sigma_A_mult, sigma_A, tmp_sum, parameters->curve);

    uECC_point_add(g_s_r, sigma_A_mult, t_new, parameters->curve);

    SHA256 newHash;
    //newHash.reset();
    uECC_word_t* resultHash_new = new uECC_word_t[HASH_SIZE]();
    hashUpdate(sigma_A, parameters->nativeNCount * 2, parameters->byteCount * 2, &newHash);
    hashUpdate(t_new, parameters->nativeNCount * 2, parameters->byteCount * 2, &newHash);
    hashUpdate(nonce, parameters->nativeNCount, parameters->byteCount, &newHash);
    //newHash.finalize(resultHash_new, HASH_SIZE);
    uint8_t* placeholder2 = new uint8_t[HASH_SIZE]();

    placeholder2 = newHash.digest();
    uECC_vli_bytesToNative(resultHash_new, placeholder2, HASH_SIZE);

    uECC_word_t* e_new = new uECC_word_t[parameters->nativeNCount]();
    //uECC_vli_bytesToNative(e_new, resultHash_new, byteCount);
    uECC_vli_mmod(e_new, resultHash_new, parameters->n, parameters->nativeNCount);

    return 0 == memcmp(e, e_new, parameters->nativeNCount);
}