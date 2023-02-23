// MOKtry.cpp : Tento soubor obsahuje funkci main. Provádění programu se tam zahajuje a ukončuje.
//

#include <iostream>
#include <uECC_vli.h>

#include <wbb.hpp>
#include<nizkpk_join.hpp>
#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "MOKtry.hpp"
#include <time.h>

// Spuštění programu: Ctrl+F5 nebo nabídka Ladit > Spustit bez ladění
// Ladění programu: F5 nebo nabídka Ladit > Spustit ladění

// Tipy pro zahájení práce:
//   1. K přidání nebo správě souborů použijte okno Průzkumník řešení.
//   2. Pro připojení ke správě zdrojového kódu použijte okno Team Explorer.
//   3. K zobrazení výstupu sestavení a dalších zpráv použijte okno Výstup.
//   4. K zobrazení chyb použijte okno Seznam chyb.
//   5. Pokud chcete vytvořit nové soubory kódu, přejděte na Projekt > Přidat novou položku. Pokud chcete přidat do projektu existující soubory kódu, přejděte na Projekt > Přidat existující položku.
//   6. Pokud budete chtít v budoucnu znovu otevřít tento projekt, přejděte na Soubor > Otevřít > Projekt a vyberte příslušný soubor .sln.
uint8_t* tutu(uint8_t n[], uint8_t man_sec[], uint8_t client_key[], int byteCount, uECC_word_t* randomReturn, uECC_Curve curve) {

    // Values init
    //const char* q_EC = "0100000000000000000001f4c8f927aed3ca752257";
    //char* q_EC = reinterpret_cast<char*>(n);
   /* printf("bytecount: %d:", 20);
    printf("\n");

    for (int i = 0; i < 10; i++) {
        printf("%x", q_EC[i]);
    }*/
    //char* q_EC = "74";

    Setup_SGM setup;
    Manager_S m_secret;

    clock_t startsetup = clock() / (CLOCKS_PER_SEC / 1000);
    generate_nizkpk_setup(&setup, &m_secret, n, man_sec, byteCount);
    clock_t endsetup = clock() / (CLOCKS_PER_SEC / 1000);
    printf("setup took %d ms \n", (endsetup - startsetup));
    //JSON_serialize_Setup_par(&setup);
    //Setup_SGM setup2;
    //JSON_deserialize_Setup_par(&setup2);


    E_1 e1 = generate_e1(&setup, &m_secret);

    //JSON_serialize_e1(&e1);
    //E_1 e11;
    //JSON_deserialize_e1(&e11);


    Sender_S s_secret;
    E_2 e2 = generate_e2(&setup, &s_secret, &e1, client_key, byteCount);

    //JSON_serialize_e2(&e2);
    //E_2 e22;
    //JSON_deserialize_e2(&e22);


    Sig_star sig = decrypt_e2(&setup, &m_secret, &e2);

    //JSON_serialize_sig_star(&sig);
    //Sig_star sig2;
    //JSON_deserialize_sig_star(&sig2);

    int verify = verify_sig(&sig, &m_secret, &s_secret, &setup);
    if (verify == 1) {
        printf("ERROR: Test NOT conducted successfully\n");
    }

    //ZK
    ZK_man zk;
    ZK_man_private zk_priv;
    ZK_issuer_create(&m_secret, &setup, &zk, &zk_priv);

    //ZK_compute_Ts_Issuer(&m_secret,&setup, &zk, &zk_priv);
    //generate_E_for_PK(&setup, &zk);
    //ZK_compute_Zs_Issuer(&m_secret, &setup, &zk, &zk_priv);
    
    if (check_issuer_proof_NI(&setup, &zk, &e1))
        printf("ZK checked sucesfully\n");
    else
    {
        printf("ZK failed \n");
    }

    /*mpz_t inv;
    mpz_init(inv);
    mpz_invert(inv, s_secret.r1, setup.q_EC);
    mpz_mul(sig.sig_star, sig.sig_star, inv);
    mpz_mod(sig.sig_star, sig.sig_star, setup.q_EC);*/
    ZK_user zk2;
    generate_ZK_user(&setup,  &zk2, &s_secret, &e1,&e2, curve);
    check_PK_user(&setup, &zk2, &e2,&e1,curve);
    

    
    if (byteCount == 20) {
        uint8_t expik[20];
        mpz_export(expik, NULL, 1, sizeof(expik[0]), 0, 0, sig.sig_star);
        uint8_t rand[20];
        mpz_export(rand, NULL, 1, sizeof(rand[0]), 0, 0, s_secret.r1);
        uECC_vli_bytesToNative(randomReturn, rand, byteCount); //we return randomized sum

        return expik;
    }
    else if (byteCount == 24) {
        uint8_t expik[24];
        mpz_export(expik, NULL, 1, sizeof(expik[0]), 0, 0, sig.sig_star);
        uint8_t rand[24];
        mpz_export(rand, NULL, 1, sizeof(rand[0]), 0, 0, s_secret.r1);
        uECC_vli_bytesToNative(randomReturn, rand, byteCount);
        return expik;
    }
    else if (byteCount == 28) {
        uint8_t expik[28];
        mpz_export(expik, NULL, 1, sizeof(expik[0]), 0, 0, sig.sig_star);
        uint8_t rand[28];
        mpz_export(rand, NULL, 1, sizeof(rand[0]), 0, 0, s_secret.r1);
        uECC_vli_bytesToNative(randomReturn, rand, byteCount);
        return expik;
    }
    else {
        uint8_t expik[32];
        mpz_export(expik, NULL, 1, sizeof(expik[0]), 0, 0, sig.sig_star);
        uint8_t rand[32];
        mpz_export(rand, NULL, 1, sizeof(rand[0]), 0, 0, s_secret.r1);
        uECC_vli_bytesToNative(randomReturn, rand, byteCount);
        return expik;
    }



    //char  c{ '\0' };
    //char* pchar{ &c };
    //mpz_get_str(pchar, 16, sig.sig_star);

    //gmp_printf("Sk_m: %Zd\n", m_secret.sk_m);
    //gmp_printf("Sk_i: %Zd\n", s_secret.sk_i);


    //gmp_printf("r: %Zd\n", m_secret.r);
    //gmp_printf("r1: %Zd\n", s_secret.r1);
    //gmp_printf("r2: %Zd\n", s_secret.r2);
    //gmp_printf("r_bar: %Zd\n", s_secret.r_bar);

    return NULL;
}


void setup()
{
    // put your setup code here, to run once:
    //Serial.begin(9600);
    //uECC_set_rng(&RandomNumberGenerator);

    int c;
    const struct uECC_Curve_t* curves[5];
    int num_curves = 0;
    bool compareWithNormal = true;
  
#if uECC_SUPPORTS_secp160r1
    curves[num_curves++] = uECC_secp160r1();
    
#endif
#if uECC_SUPPORTS_secp192r1
    curves[num_curves++] = uECC_secp192r1();
    
#endif
#if uECC_SUPPORTS_secp224r1
    curves[num_curves++] = uECC_secp224r1();
#endif
#if uECC_SUPPORTS_secp256r1
    curves[num_curves++] = uECC_secp256r1();
#endif
#if uECC_SUPPORTS_secp256k1
    curves[num_curves++] = uECC_secp256k1();
#endif

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

        //long a = millis();
        //issueModified(&parameters, &m_list, &x_list, sigma, &sigma_list,client_private);
        //issue(&parameters, &m_list, &x_list, sigma, &sigma_list);
        // 
        //here we have 2party issue
        
        printf("Starting the issue algorithms...\n");
        clock_t startIssue = clock() / (CLOCKS_PER_SEC / 1000);
        uECC_word_t* sum = new uECC_word_t[nativeNCount]();
        SignGFirstHalf(&x_list, &m_list, &parameters, sum);

        printf("Starting the 2-party computation...\n");
        clock_t start = clock() / (CLOCKS_PER_SEC / 1000); //in ms

        uECC_word_t* randInTwoParty = new uECC_word_t[nativeNCount]();
        uint8_t* gotBack;
        if (curve == uECC_secp160r1()) {
            uint8_t nBytes[20];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[20];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[24];
            
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = tutu(nBytes, man_Sec, client_Sec, 20, randInTwoParty,curve);
            
          

        }
        else if (curve == uECC_secp192r1()) {

            uint8_t nBytes[24];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[24];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[24];
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = tutu(nBytes, man_Sec, client_Sec, 24, randInTwoParty,curve);
        }
        else if (curve == uECC_secp224r1()) {

            uint8_t nBytes[28];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[28];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[28];
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = tutu(nBytes, man_Sec, client_Sec, 28, randInTwoParty,curve);
        }
        else {
            uint8_t nBytes[32];
            uECC_vli_nativeToBytes(nBytes, byteCount, n);
            uint8_t man_Sec[32];
            uECC_vli_nativeToBytes(man_Sec, byteCount, sum);
            uint8_t client_Sec[32];
            uECC_vli_nativeToBytes(client_Sec, byteCount, client_private);
            gotBack = tutu(nBytes, man_Sec, client_Sec, 32, randInTwoParty,curve);
            
        }
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

        
        
        //std::cout << std::hex << static_cast<int>(sigmaBytes) << std::endl;

        //long b = millis();

        //Serial.print(" || ");
        //Serial.print(b - a);

        uECC_word_t* nonce = new uECC_word_t[nativeNCount]();
        uECC_generate_random_int(nonce, n, nativeNCount);

        //a = millis();
        //declare(&parameters, nonce, sigma, &sigma_list, &m_list, sigma_A, e, s_r, &s_m_list);

        uECC_word_t* S_k = new uECC_word_t[nativeNCount]();
        clock_t startDeclare = clock() / (CLOCKS_PER_SEC / 1000);
        declareModified(&parameters, nonce, sigma, &sigma_list, &m_list, sigma_A, e, s_r, &s_m_list,client_private,S_k);
        clock_t endDeclare = clock() / (CLOCKS_PER_SEC / 1000);

        printf("The declare algorithm is done, it took %d ms \n", (endDeclare-startDeclare));
        //b = millis();
        //Serial.print(" | ");
        //Serial.print(b - a);

        //a = millis();
        //bool passed = verify(&parameters, e, nonce, &s_m_list, s_r, sigma_A, &x_list, &m_list);
        clock_t startVer = clock() / (CLOCKS_PER_SEC / 1000);
        bool passed = verifyModified(&parameters, e, nonce, &s_m_list, s_r, sigma_A, &x_list, &m_list,S_k);
        clock_t endVer = clock() / (CLOCKS_PER_SEC / 1000);
        //b = millis();
        //Serial.print(" | ");
        //Serial.print(b - a);

        printf(passed ? "Result of KVAC verification: PASSED" : " Result of KVAC verification: FAILED");
        printf("\n");
        printf("Verification took %d ms.\n",(endVer-startVer));
       


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
        //Serial.println();
    }
}



int main()
{
    
    setup();
    
    //tutu();
}
/*extern "C" {
    __declspec(dllexport) int workPls() {
        setup();
    }
}*/