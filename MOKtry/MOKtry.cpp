// MOKtry.cpp : Tento soubor obsahuje funkci main. Provádění programu se tam zahajuje a ukončuje.
//

#include <iostream>
#include "uECC_vli.h"

#include "wbb.hpp"
#include "nizkpk_join.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "MOKtry.hpp"
#include <time.h>

//this function runs the NIZKPK, it takes the N of the curve, man_sec is the issuer d (x0+x1m1... it is the otput from first half of issue), clients sk
//randomReturn is the pointer where the client r1 is returned and curve is the curve used
uint8_t* runNIZKPKForKVAC(uint8_t n[], uint8_t man_sec[], uint8_t client_key[], int byteCount, uECC_word_t* randomReturn, uECC_Curve curve) {


    Setup_SGM setup;
    Manager_S m_secret;

    clock_t start = clock() / (CLOCKS_PER_SEC / 1000);

    generate_nizkpk_setup(&setup, &m_secret, n, man_sec, byteCount);

    clock_t end = clock() / (CLOCKS_PER_SEC / 1000);
    printf("setup took %d ms \n", (end - start));
    
    clock_t start_part, end_part;
    start_part = clock() / (CLOCKS_PER_SEC / 1000);
    start = clock() / (CLOCKS_PER_SEC / 1000);

    E_1 e1 = generate_e1(&setup, &m_secret);

    end_part= clock() / (CLOCKS_PER_SEC / 1000);
    printf("Manager e1 took %d ms \n", (end_part - start_part));
    ZK_man zk;
    ZK_man_private zk_priv;
    start_part = clock() / (CLOCKS_PER_SEC / 1000);

    ZK_issuer_create(&m_secret, &setup, &zk, &zk_priv);

    end_part = clock() / (CLOCKS_PER_SEC / 1000);
    printf("Manager ZK took %d ms \n", (end_part - start_part));
    end = clock() / (CLOCKS_PER_SEC / 1000);
    printf("Manager zk and e1 took %d ms \n", (end - start));

    start_part = clock() / (CLOCKS_PER_SEC / 1000);
    start = clock() / (CLOCKS_PER_SEC / 1000);

    if (check_issuer_proof_NI(&setup, &zk, &e1))
        printf("ZK checked sucesfully\n");
    else
    {
        printf("ZK failed \n");
    }
    //JSON_serialize_e1(&e1);
    //E_1 e11;
    //JSON_deserialize_e1(&e11);
    end_part = clock() / (CLOCKS_PER_SEC / 1000);
    printf("Check of man ZK took %d ms \n", (end_part - start_part));
    Sender_S s_secret;
    start_part = clock() / (CLOCKS_PER_SEC / 1000);

    E_2 e2 = generate_e2(&setup, &s_secret, &e1, client_key, byteCount);

    end_part = clock() / (CLOCKS_PER_SEC / 1000);
    printf("E2 took %d ms \n", (end_part - start_part));
    start_part = clock() / (CLOCKS_PER_SEC / 1000);
    ZK_user zk2;

    generate_ZK_user(&setup, &zk2, &s_secret, &e1, &e2, curve);

    end_part = clock() / (CLOCKS_PER_SEC / 1000);
    printf("ZK user took %d ms \n", (end_part - start_part));
    end = clock() / (CLOCKS_PER_SEC / 1000);
    printf("User check, zk and e2 took %d ms \n", (end - start));

    start = clock() / (CLOCKS_PER_SEC / 1000);

    start_part = clock() / (CLOCKS_PER_SEC / 1000);

    check_PK_user(&setup, &zk2, &e2, &e1, curve);

    end_part = clock() / (CLOCKS_PER_SEC / 1000);
    printf("ZK check user took %d ms \n", (end_part - start_part));
   

    start_part = clock() / (CLOCKS_PER_SEC / 1000);

    Sig_star sig = decrypt_e2(&setup, &m_secret, &e2);

    end_part = clock() / (CLOCKS_PER_SEC / 1000);
    printf("DEC took %d ms \n", (end_part - start_part));

    end = clock() / (CLOCKS_PER_SEC / 1000);
    printf("manager dec and check zk took %d ms \n", (end - start));
   
    
    uint8_t* expik = (uint8_t*)malloc(byteCount * sizeof(uint8_t));
    uint8_t* rand = (uint8_t*)malloc(byteCount * sizeof(uint8_t));
    mpz_export(expik, NULL, 1, sizeof(expik[0]), 0, 0, sig.sig_star);
    mpz_export(rand, NULL, 1, sizeof(rand[0]), 0, 0, s_secret.r1);
    uECC_vli_bytesToNative(randomReturn, rand, byteCount); //we return randomized sum
    free(rand);
    return expik;
    
}

//the setup code from KVAC now modified, you can uncomment the other curves if you want it test for all the curves
void setup()
{

    int c;
    const struct uECC_Curve_t* curves[5];
    int num_curves = 0;
    bool compareWithNormal = true;
 /*
#if uECC_SUPPORTS_secp160r1
    curves[num_curves++] = uECC_secp160r1();
    
#endif
#if uECC_SUPPORTS_secp192r1
    curves[num_curves++] = uECC_secp192r1();
    
#endif
#if uECC_SUPPORTS_secp224r1
    curves[num_curves++] = uECC_secp224r1();
#endif*/
#if uECC_SUPPORTS_secp256r1
    curves[num_curves++] = uECC_secp256r1();
#endif/*
#if uECC_SUPPORTS_secp256k1
    curves[num_curves++] = uECC_secp256k1();
#endif*/
    clock_t start_1, end_1;



    for (c = 0; c < num_curves; ++c)
    {
        const struct uECC_Curve_t* curve = curves[c];
        if (curve == uECC_secp160r1())
            printf("Testing curve secp160r1... \n");
        else if(curve== uECC_secp192r1())
            printf("Testing curve secp192r1... \n");
        else if(curve == uECC_secp224r1())
            printf("Testing curve secp224r1... \n");
        else if (curve == uECC_secp256r1())
            printf("Testing curve secp256r1... \n");
        else if (curve == uECC_secp256k1())
            printf("Testing curve secp256k1... \n");
        
        const uECC_word_t* n = uECC_curve_n(curve);
        const uECC_word_t* g = uECC_curve_G(curve);
        const wordcount_t nativeCount = uECC_curve_num_words(curve);
        const wordcount_t nativeNCount = uECC_curve_num_n_words(curve);
        const wordcount_t byteCount = uECC_curve_num_bytes(curve);

        uECC_Parameters_t parameters(curve);

        uECC_word_t* m1 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m2 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m3 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m4 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m5 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m6 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m7 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m8 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m9 = new uECC_word_t[nativeNCount]();
        uECC_word_t* m10 = new uECC_word_t[nativeNCount]();

        uECC_word_t* x0 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x1 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x2 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x3 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x4 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x5 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x6 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x7 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x8 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x9 = new uECC_word_t[nativeNCount]();
        uECC_word_t* x10 = new uECC_word_t[nativeNCount]();

        uECC_word_t* sigma = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x1 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x2 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x3 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x4 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x5 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x6 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x7 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x8 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x9 = new uECC_word_t[nativeNCount * 2]();
        uECC_word_t* sigma_x10 = new uECC_word_t[nativeNCount * 2]();

        uECC_word_t* e = new uECC_word_t[nativeNCount]();

        uECC_word_t* s_r = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m1 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m2 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m3 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m4 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m5 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m6 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m7 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m8 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m9 = new uECC_word_t[nativeNCount]();
        uECC_word_t* s_m10 = new uECC_word_t[nativeNCount]();

        uECC_word_t* sigma_A = new uECC_word_t[nativeNCount * 2]();

        uECC_Element_t x0_el(x0, nativeNCount);
        uECC_Element_t x1_el(x1, nativeNCount);
        uECC_Element_t x2_el(x2, nativeNCount);
        uECC_Element_t x3_el(x3, nativeNCount);
        uECC_Element_t x4_el(x4, nativeNCount);
        uECC_Element_t x5_el(x5, nativeNCount);
        uECC_Element_t x6_el(x6, nativeNCount);
        uECC_Element_t x7_el(x7, nativeNCount);
        uECC_Element_t x8_el(x8, nativeNCount);
        uECC_Element_t x9_el(x9, nativeNCount);
        uECC_Element_t x10_el(x10, nativeNCount);

        uECC_Element_t m1_el(m1, nativeNCount);
        uECC_Element_t m2_el(m2, nativeNCount);
        uECC_Element_t m3_el(m3, nativeNCount);
        uECC_Element_t m4_el(m4, nativeNCount);
        uECC_Element_t m5_el(m5, nativeNCount);
        uECC_Element_t m6_el(m6, nativeNCount);
        uECC_Element_t m7_el(m7, nativeNCount);
        uECC_Element_t m8_el(m8, nativeNCount);
        uECC_Element_t m9_el(m9, nativeNCount);
        uECC_Element_t m10_el(m10, nativeNCount);

        uECC_Element_t s_m1_el(s_m1, nativeNCount);
        uECC_Element_t s_m2_el(s_m2, nativeNCount);
        uECC_Element_t s_m3_el(s_m3, nativeNCount);
        uECC_Element_t s_m4_el(s_m4, nativeNCount);
        uECC_Element_t s_m5_el(s_m5, nativeNCount);
        uECC_Element_t s_m6_el(s_m6, nativeNCount);
        uECC_Element_t s_m7_el(s_m7, nativeNCount);
        uECC_Element_t s_m8_el(s_m8, nativeNCount);
        uECC_Element_t s_m9_el(s_m9, nativeNCount);
        uECC_Element_t s_m10_el(s_m10, nativeNCount);

        uECC_Element_t sigma_x1_el(sigma_x1, nativeNCount * 2);
        uECC_Element_t sigma_x2_el(sigma_x2, nativeNCount * 2);
        uECC_Element_t sigma_x3_el(sigma_x3, nativeNCount * 2);
        uECC_Element_t sigma_x4_el(sigma_x4, nativeNCount * 2);
        uECC_Element_t sigma_x5_el(sigma_x5, nativeNCount * 2);
        uECC_Element_t sigma_x6_el(sigma_x6, nativeNCount * 2);
        uECC_Element_t sigma_x7_el(sigma_x7, nativeNCount * 2);
        uECC_Element_t sigma_x8_el(sigma_x8, nativeNCount * 2);
        uECC_Element_t sigma_x9_el(sigma_x9, nativeNCount * 2);
        uECC_Element_t sigma_x10_el(sigma_x10, nativeNCount * 2);

        uECC_List_t m_list(&m1_el);
        uECC_List_t s_m_list(&s_m1_el);
        uECC_List_t sigma_list(&sigma_x1_el);
        uECC_List_t x_list(&x0_el);
        x_list.add(&x1_el);
        x_list.add(&x2_el);
        x_list.add(&x3_el);
        x_list.add(&x4_el);
        x_list.add(&x5_el);
        x_list.add(&x6_el);
        x_list.add(&x7_el);
        x_list.add(&x8_el);
        x_list.add(&x9_el);
        x_list.add(&x10_el);

        m_list.add(&m2_el);
        m_list.add(&m3_el);
        m_list.add(&m4_el);
        m_list.add(&m5_el);
        m_list.add(&m6_el);
        m_list.add(&m7_el);
        m_list.add(&m8_el);
        m_list.add(&m9_el);
        m_list.add(&m10_el);

        s_m_list.add(&s_m2_el);
        s_m_list.add(&s_m3_el);
        s_m_list.add(&s_m4_el);
        s_m_list.add(&s_m5_el);
        s_m_list.add(&s_m6_el);
        s_m_list.add(&s_m7_el);
        s_m_list.add(&s_m8_el);
        s_m_list.add(&s_m9_el);
        s_m_list.add(&s_m10_el);

        sigma_list.add(&sigma_x2_el);
        sigma_list.add(&sigma_x3_el);
        sigma_list.add(&sigma_x4_el);
        sigma_list.add(&sigma_x5_el);
        sigma_list.add(&sigma_x6_el);
        sigma_list.add(&sigma_x7_el);
        sigma_list.add(&sigma_x8_el);
        sigma_list.add(&sigma_x9_el);
        sigma_list.add(&sigma_x10_el);

        x_list.length = ISSUED + 1;
        m_list.length = ISSUED;
        s_m_list.length = ISSUED;
        sigma_list.length = ISSUED;

        fillWithRandoms(&m_list, &parameters);
        fillWithRandoms(&x_list, &parameters);

        //here starts experimentation
        uECC_word_t* client_private = new uECC_word_t[nativeNCount]();
        uECC_generate_random_int(client_private, n, nativeNCount);

        //here we have 2party issue
        printf("Starting the issue algorithms...\n");
        clock_t startIssue = clock() / (CLOCKS_PER_SEC / 1000);
        uECC_word_t* sum = new uECC_word_t[nativeNCount]();
        //the first part computes the d as (x0+x1m1+...xnmn) 
        SignGFirstHalf(&x_list, &m_list, &parameters, sum);

        printf("Starting the 2-party computation...\n");
        clock_t start = clock() / (CLOCKS_PER_SEC / 1000); //in ms

        uECC_word_t* randInTwoParty = new uECC_word_t[nativeNCount]();
        uint8_t* gotBack;

        //dynamic allocation for parameters that have to be passed to the NIZKPK part, this might not work for the smallest curve, as there are some problems with the representing of the numbers
        uint8_t *nBytes= (uint8_t*)malloc(byteCount * sizeof(uint8_t));
        uint8_t *man_Sec = (uint8_t*)malloc(byteCount * sizeof(uint8_t));
        uint8_t * client_Sec= (uint8_t*)malloc(byteCount * sizeof(uint8_t));
        uECC_vli_nativeToBytes(nBytes, byteCount, n);
        uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
        uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
        gotBack = runNIZKPKForKVAC(nBytes, man_Sec, client_Sec, byteCount, randInTwoParty, curve);
        free(nBytes);
        free(man_Sec);
        free(client_Sec);
        //this was before malloc was used, now should not be used if the allocation works fine
        /*
        if (curve == uECC_secp160r1()) {
            uint8_t nBytes[20];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[20];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[24];      
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = runNIZKPKForKVAC(nBytes, man_Sec, client_Sec, 20, randInTwoParty,curve);
        }
        else if (curve == uECC_secp192r1()) {

            uint8_t nBytes[24];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[24];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[24];
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = runNIZKPKForKVAC(nBytes, man_Sec, client_Sec, 24, randInTwoParty,curve);
        }
        else if (curve == uECC_secp224r1()) {

            uint8_t nBytes[28];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[28];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[28];
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = runNIZKPKForKVAC(nBytes, man_Sec, client_Sec, 28, randInTwoParty,curve);
        }
        else {
            uint8_t nBytes[32];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[32];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[32];
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = runNIZKPKForKVAC(nBytes, man_Sec, client_Sec, 32, randInTwoParty,curve);
            
        }*/
        uECC_vli_bytesToNative(sum, gotBack, byteCount);
       
        clock_t end = clock() / (CLOCKS_PER_SEC / 1000); //in ms
        printf("2-party computation done, it took %d ms in total. \n", (end - start));

        SignGSecondHalf(&x_list, &m_list, &parameters, sigma, sum);
        signSigma(sigma, &x_list, &parameters, &sigma_list);
        
        //here we remove the r1 from sigmas ie. the client derandomizes sigmas, but the issuer doesnt know sigmas
        uECC_point_mult(sigma, sigma, randInTwoParty, curve);
        for (int i = 0; i < ISSUED; i++) {
            uECC_point_mult(sigma_list.get(i)->content, sigma_list.get(i)->content, randInTwoParty, curve);
        }
        clock_t endIssue = clock() / (CLOCKS_PER_SEC / 1000);
        printf("Issue algorithms and derandomizing of sigmas is done. Issuing took %d ms in total.\n",(endIssue-startIssue));

        
        
      

        uECC_word_t* nonce = new uECC_word_t[nativeNCount]();
        uECC_generate_random_int(nonce, n, nativeNCount);

        uECC_word_t* S_k = new uECC_word_t[nativeNCount]();
        clock_t startDeclare = clock() / (CLOCKS_PER_SEC / 1000);
       
        declareModified(&parameters, nonce, sigma, &sigma_list, &m_list, sigma_A, e, s_r, &s_m_list,client_private,S_k);
       
        

        clock_t endDeclare = clock() / (CLOCKS_PER_SEC / 1000);
        
        double time_taken = endDeclare - startDeclare; // in miliseconds

        printf("The declare algorithm is done, it took %f ms \n", (time_taken));
        
        clock_t startVer = clock() ;
        
        bool passed = verifyModified(&parameters, e, nonce, &s_m_list, s_r, sigma_A, &x_list, &m_list,S_k);
        clock_t endVer = clock();
        
        time_taken = endVer-startVer; 
        

        printf(passed ? "Result of KVAC verification: PASSED" : " Result of KVAC verification: FAILED");
        printf("\n");
        printf("Verification took %f s.\n",(time_taken));
       


        //here we test the normal functions will it work?
        if (compareWithNormal) {
            printf("Now testing the unmodified KVAC for speed comparasion...\n");
            start = clock() / (CLOCKS_PER_SEC / 1000);
            issue(&parameters, &m_list, &x_list, sigma, &sigma_list);
            end = clock() / (CLOCKS_PER_SEC / 1000);
            printf("Issue algorithm took %d ms. \n", (end - start));

            startDeclare = clock() / (CLOCKS_PER_SEC / 1000);
            declare(&parameters, nonce, sigma, &sigma_list, &m_list, sigma_A, e, s_r, &s_m_list);
            endDeclare = clock() / (CLOCKS_PER_SEC / 1000);
            printf("The declare algorithm is done, it took %d ms \n", (endDeclare - startDeclare));

            startVer = clock() / (CLOCKS_PER_SEC / 1000);
            passed = verify(&parameters, e, nonce, &s_m_list, s_r, sigma_A, &x_list, &m_list);
            endVer = clock() / (CLOCKS_PER_SEC / 1000);
            printf(passed ? "Result of KVAC verification: PASSED" : " Result of KVAC verification: FAILED");
            printf("\n");
            printf("Verification took %d ms.\n", (endVer - startVer));
            
        }
        printf("\n");
        
    }
}



int main()
{
    
    setup();
    
}
