#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "nizkpk_join.hpp"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>
#include <SHA256.h>
#include <time.h>
#define kappa 3

const char* SETUP_JSON_OUT = "{\n\t\"n\": \"%s\",\n\t\"g\": \"%s\",\n\t\"h\": \"%s\",\n\t\"n_goth\": \"%s\",\n\t\"g_goth\": \"%s\",\n\t\"h_goth\": \"%s\",\n\t\"q_EC\": \"%s\"\n}";
const char* E1_JSON_OUT = "{\n\t\"e_1\": \"%s\",\n\t\"c_goth\": \"%s\"\n}";
const char* E2_JSON_OUT = "{\n\t\"e_2\": \"%s\",\n\t\"c2_goth\": \"%s\"\n}";
const char* SIG_STAR_JSON_OUT = "{\n\t\"sig_star\": \"%s\"\n}";



const char* SETUP_JSON_IN = "{\n\t\"n\": \"%[^\"]\",\n\t\"g\": \"%[^\"]\",\n\t\"h\": \"%[^\"]\",\n\t\"n_goth\": \"%[^\"]\",\n\t\"g_goth\": \"%[^\"]\",\n\t\"h_goth\": \"%[^\"]\",\n\t\"q_EC\": \"%[^\"]\"\n}";
const char* E1_JSON_IN = "{\n\t\"e_1\": \"%[^\"]\",\n\t\"c_goth\": \"%[^\"]\"\n}";
const char* E2_JSON_IN = "{\n\t\"e_2\": \"%[^\"]\",\n\t\"c2_goth\": \"%[^\"]\"\n}";
const char* SIG_STAR_JSON_IN = "{\n\t\"sig_star\": \"%[^\"]\"\n}";


void get_rand_seed(void* buf, int len)
{
	//FILE* fp;
	void* p;

	//fp = fopen("/dev/urandom", "r");

	p = buf;
	while (len>0)
	{
		size_t s;
        s = rand();
        //printf("s:%d  ", s);
        p = static_cast<char*>(p) + s;
        
        int numberOfBits = floor(log2(s)) + 1;
        len = len - numberOfBits;

        //printf("len: %d  ", len);
	}
    
   
    
	//fclose(fp);
   
    
}

void generate_g(mpz_t* n, mpz_t* n2, mpz_t* phi, mpz_t* g) {


    mpz_t i;
    mpz_init(i);

    mpz_t k;
    mpz_init(k);

    do{

        generate_r_from_group(n, &k);
        mpz_powm(*g, k, *n, *n2);
        mpz_powm(i, *g, *phi, *n2);
        //printf("looping here");
    }while(mpz_cmp_ui(i, 1) != 0);

    mpz_clear(i);
    mpz_clear(k);


}


void generate_r_from_group(mpz_t* mod, mpz_t* r){
    
    int len = 512;
    mpz_t s;
	mpz_init(s);
    void* buf;
	buf = malloc(len);
	get_rand_seed(buf, len);
	mpz_import(s, len, 1, 1, 0, 0, buf);

    gmp_randstate_t rand;
    gmp_randinit_default(rand);
    gmp_randseed(rand, s);

    mpz_urandomm(*r, rand, *mod);
    
    gmp_randclear(rand);
    mpz_clear(s);
    free(buf);

}

void generate_r_from_bitlenght(size_t length, mpz_t* r){
    
    int len = 512;
    mpz_t s;
	mpz_init(s);
    void* buf;
	buf = malloc(len);
    
	/*get_rand_seed(buf, len);
    printf("done");
	mpz_import(s, len, 1, 1, 0, 0, buf);*/
    mpz_random(s,length);

    //gmp_printf("attempt rakovina: %Zd \n", s);
    gmp_randstate_t rand;
    gmp_randinit_default(rand);
    gmp_randseed(rand,s);

    mpz_urandomb(*r, rand, length);
    
    
    gmp_randclear(rand);
    mpz_clear(s);
    free(buf);


}

void generate_RSA_SSL(mpz_t* p, mpz_t* q, mpz_t* n, size_t size){

    /*BIGNUM* p_big = BN_new();
    BIGNUM *q_big = BN_new();
    BIGNUM *n_big = BN_new();*/

    size *= 3*kappa;

    //clock_t start, end;
    double cpu_time_used;
    
    generate_r_from_bitlenght( size/2+1,p);
    
    generate_r_from_bitlenght(size/2+1,q);
    
    mpz_nextprime(*p, *p);

    mpz_nextprime(*q, *q);
    //char  c{ '\0' };
    //char* pchar{ &c };
    //mpz_get_str(pchar, 16, *p);
    //gmp_printf("P is: %Zd \n", p);
    //BN_CTX *ctx = BN_CTX_secure_new();
    //BN_generate_prime_ex2(p_big, size/2+1, 1, NULL, NULL, NULL, ctx);
    //BN_generate_prime_ex2(q_big, size/2+1, 1, NULL, NULL, NULL, ctx);
    /*
    char* p_hex = BN_bn2hex(p_big);
    char* q_hex = BN_bn2hex(q_big);

    mpz_set_str(*p, p_hex, 16);
    mpz_set_str(*q, q_hex, 16);
    */
    mpz_mul(*n, *p, *q);
    /*
    BN_free(p_big);
    BN_free(q_big);
    BN_free(n_big);
    BN_CTX_free(ctx);
    OPENSSL_free(p_hex);
    OPENSSL_free(q_hex);
    */
}



void generate_nizkpk_setup(Setup_SGM* setup, Manager_S* m_secret, uint8_t q_EC[], uint8_t manKey[], int byteCount) {
    
    //EC params
    mpz_inits(setup->q_EC, NULL);
    //mpz_set_str(setup->q_EC, q_EC, 16);
    
    if (byteCount == 20) {
        const char* q_EC = "0100000000000000000001f4c8f927aed3ca752257";
        
        mpz_set_str(setup->q_EC, q_EC, 16);

    }

    else {
        mpz_import(setup->q_EC, byteCount, 1, sizeof(q_EC[0]), 0, 0, q_EC);
    }
    //mpz_set_ui(setup->q_EC,q_EC);
    //printf("sizeOFQEC= %d", sizeof(q_EC));
    //RSA params generation impl
    mpz_t p_n;
    mpz_init(p_n);

    mpz_t q_n;
    mpz_init(q_n);

    mpz_t q2;
    mpz_init(q2);
    mpz_pow_ui(q2, setup->q_EC, 2);

    size_t size = mpz_sizeinbase(q2, 2) + 1;
    
    mpz_init(setup->n);
    generate_RSA_SSL(&p_n, &q_n, &setup->n, size);
    
    mpz_inits(setup->n_goth, setup->h_goth, setup->g_goth, m_secret->phi_n_goth, NULL);

    mpz_t p_ng;
    mpz_init(p_ng);
    mpz_t q_ng;
    mpz_init(q_ng);

    mpz_t rand_goth;
    mpz_init(rand_goth);

    //Gothics
    generate_RSA_SSL(&p_ng, &q_ng, &setup->n_goth, size);
    
    generate_r_from_group(&setup->n_goth, &setup->h_goth);
    //printf("GOTH DONE");
    mpz_sub_ui(p_ng, p_ng, 1);
    mpz_sub_ui(q_ng, q_ng, 1);
    mpz_mul(m_secret->phi_n_goth, p_ng, q_ng);

    generate_r_from_group(&m_secret->phi_n_goth, &rand_goth);

    mpz_powm(setup->g_goth, setup->h_goth, rand_goth, setup->n_goth);



    //Secrets impl
    //modification here 
    mpz_init(m_secret->sk_m);
    mpz_import(m_secret->sk_m, byteCount, 1, sizeof(manKey[0]), 0, 0, manKey);
    //gmp_printf("attempt 3: %Zd \n", m_secret->sk_m);
    //generate_r_from_group(&setup->q_EC, &m_secret->sk_m);

    mpz_inits(setup->g, setup->h, setup->n2, m_secret->phi_n, NULL);

    mpz_add_ui(setup->h, setup->n, 1);

    mpz_pow_ui(setup->n2, setup->n, 2);
    mpz_sub_ui(p_n, p_n, 1);
    mpz_sub_ui(q_n, q_n, 1);
    mpz_mul(m_secret->phi_n, p_n, q_n);

    mpz_t two;
    mpz_init(two);
    mpz_set_ui(two, 2);

    mpz_init(setup->n_half);
    mpz_fdiv_q(setup->n_half, setup->n, two);

    //printf("generation next ");
    //G generation
    generate_g(&setup->n, &setup->n2, &m_secret->phi_n, &setup->g);

    printf("size of n: %zu\n", mpz_sizeinbase(setup->n, 2));
    printf("size of g: %zu\n", mpz_sizeinbase(setup->g, 2));
    printf("size of h: %zu\n", mpz_sizeinbase(setup->h, 2));

    mpz_clears(two, p_n, q_n, p_ng, q_ng, q2, rand_goth, NULL);

}

E_1 generate_e1(Setup_SGM* setup, Manager_S* m_secret){

    E_1 e1;
    //Random variables impl
    mpz_init(m_secret->r);
    generate_r_from_group(&m_secret->phi_n, &m_secret->r);

    mpz_t e11;
    mpz_init(e11);

    //e1 calc
    mpz_init(e1.e1);
    mpz_add(e1.e1, setup->n_half, m_secret->sk_m);
    mpz_powm(e1.e1, setup->h, e1.e1, setup->n2);
    mpz_powm(e11, setup->g, m_secret->r, setup->n2);
    mpz_mul(e1.e1, e1.e1, e11);
    mpz_mod(e1.e1, e1.e1, setup->n2);

    mpz_inits(m_secret->r_dash, e1.c_goth, m_secret->r_dash, NULL);
    generate_r_from_group(&m_secret->phi_n_goth, &m_secret->r_dash);


    mpz_powm(e1.c_goth, setup->g_goth, m_secret->sk_m, setup->n_goth);
    mpz_powm(e11, setup->h_goth, m_secret->r_dash, setup->n_goth);
    mpz_mul(e1.c_goth, e1.c_goth, e11);
    mpz_mod(e1.c_goth, e1.c_goth, setup->n_goth);

    mpz_clear(e11);

    return e1;

}

E_2 generate_e2(Setup_SGM* setup, Sender_S* s_secret, E_1* e1, uint8_t client_sec[], int byteCount) {

    E_2 e2;

    //Secrets impl
    mpz_inits(s_secret->sk_i, s_secret->r1, s_secret->r2, s_secret->r_bar, NULL);


    size_t r2_size = mpz_sizeinbase(setup->q_EC, 2)*kappa;
    size_t rbar_size = mpz_sizeinbase(setup->n_goth, 2)*kappa;


    //generate_r_from_group(&setup->q_EC, &s_secret->sk_i);
    //modded HERE
    mpz_import(s_secret->sk_i, byteCount, 1, sizeof(client_sec[0]), 0, 0, client_sec);

    generate_r_from_group(&setup->q_EC, &s_secret->r1);
    generate_r_from_bitlenght(r2_size, &s_secret->r2);
    generate_r_from_bitlenght(r2_size, &s_secret->r_bar);
    generate_r_from_group(&setup->n, &s_secret->r_bar);

    // e2 calc
    mpz_init(e2.e2);

    mpz_t e22, e23;
    mpz_inits(e22, e23, NULL);

    mpz_powm(e23, setup->h, setup->n_half, setup->n2);
    mpz_invert(e23, e23, setup->n2);
    mpz_mul(e23, e1->e1, e23);
    mpz_powm(e23, e23, s_secret->r1, setup->n2);


    mpz_mul(e2.e2, s_secret->sk_i, s_secret->r1);
    mpz_mul(e22, s_secret->r2, setup->q_EC);
    mpz_add(e2.e2, e2.e2, e22);
    mpz_add(e2.e2, e2.e2, setup->n_half);
    mpz_powm(e2.e2, setup->h, e2.e2, setup->n2);

    mpz_powm(e22, setup->g, s_secret->r_bar, setup->n2);
    
    mpz_mul(e2.e2, e2.e2, e23);
    mpz_mul(e2.e2, e2.e2, e22);
    mpz_mod(e2.e2, e2.e2, setup->n2);

    mpz_inits(e2.c2_goth, NULL);
    mpz_powm(e2.c2_goth, setup->g_goth, s_secret->sk_i, setup->n_goth);
    mpz_powm(e22, setup->h_goth, s_secret->r_bar, setup->n_goth);
    mpz_mul(e2.c2_goth, e2.c2_goth, e22);
    mpz_mod(e2.c2_goth, e2.c2_goth, setup->n_goth);

    mpz_clears(e22, e23, NULL);

    return e2;

}

E_2 generate_e2_parallel(Setup_SGM* setup, Sender_S* s_secret, E_1* e1){

    E_2 e2;

    //Secrets impl
    mpz_inits(s_secret->sk_i, s_secret->r1, s_secret->r2, s_secret->r_bar, NULL);


    size_t r2_size = mpz_sizeinbase(setup->q_EC, 2)*kappa;
    size_t rbar_size = mpz_sizeinbase(setup->n_goth, 2)*kappa;


    generate_r_from_group(&setup->q_EC, &s_secret->sk_i);
    generate_r_from_group(&setup->q_EC, &s_secret->r1);
    generate_r_from_bitlenght(r2_size, &s_secret->r2);
    generate_r_from_bitlenght(r2_size, &s_secret->r_bar);
    generate_r_from_group(&setup->n, &s_secret->r_bar);

    // e2 calc
    mpz_init(e2.e2);

    mpz_t e22, e23;
    mpz_inits(e22, e23, NULL);

    mpz_powm(e23, setup->h, setup->n_half, setup->n2);
    mpz_invert(e23, e23, setup->n2);
    mpz_mul(e23, e1->e1, e23);
    mpz_powm(e23, e23, s_secret->r1, setup->n2);


    mpz_mul(e2.e2, s_secret->sk_i, s_secret->r1);
    mpz_mul(e22, s_secret->r2, setup->q_EC);
    mpz_add(e2.e2, e2.e2, e22);
    mpz_add(e2.e2, e2.e2, setup->n_half);
    mpz_powm(e2.e2, setup->h, e2.e2, setup->n2);

    mpz_powm(e22, setup->g, s_secret->r_bar, setup->n2);
    
    mpz_mul(e2.e2, e2.e2, e23);
    mpz_mul(e2.e2, e2.e2, e22);
    mpz_mod(e2.e2, e2.e2, setup->n2);


    mpz_inits(e2.c2_goth, NULL);
    mpz_powm(e2.c2_goth, setup->g_goth, s_secret->sk_i, setup->n_goth);
    mpz_powm(e22, setup->h_goth, s_secret->r_bar, setup->n_goth);//I modified r_bar instead of sk_i
    mpz_mul(e2.c2_goth, e2.c2_goth, e22);
    mpz_mod(e2.c2_goth, e2.c2_goth, setup->n_goth);


    mpz_clears(e22, e23, NULL);

    return e2;

}


Sig_star decrypt_e2(Setup_SGM* setup, Manager_S* m_secret, E_2* e2){


    Sig_star sig_star;

    // Decryption

    mpz_init(sig_star.sig_star);
    mpz_powm(sig_star.sig_star, e2->e2, m_secret->phi_n, setup->n2);
    mpz_sub_ui(sig_star.sig_star, sig_star.sig_star, 1);
    mpz_fdiv_q(sig_star.sig_star, sig_star.sig_star, setup->n);
    mpz_mod(sig_star.sig_star, sig_star.sig_star, setup->n2);

    mpz_t phi_inv;
    mpz_init(phi_inv);
    mpz_invert(phi_inv, m_secret->phi_n, setup->n);

    mpz_mul(sig_star.sig_star, sig_star.sig_star, phi_inv);
    mpz_mod(sig_star.sig_star, sig_star.sig_star, setup->n);
    mpz_sub(sig_star.sig_star, sig_star.sig_star, setup->n_half);
    mpz_mod(sig_star.sig_star, sig_star.sig_star, setup->n);
    mpz_mod(sig_star.sig_star, sig_star.sig_star, setup->q_EC);

    mpz_clear(phi_inv);




    return sig_star;

}


int verify_sig(Sig_star* sig, Manager_S* m_secret, Sender_S* s_secret, Setup_SGM* setup){


    mpz_t test;
    mpz_init(test);

    mpz_add(test, s_secret->sk_i, m_secret->sk_m);
    mpz_mul(test, test, s_secret->r1);
    mpz_mod(test, test, setup->q_EC);
    
    //tests here
    /*mpz_t inv;
    mpz_init(inv);
    mpz_invert(inv, s_secret->r1, setup->q_EC);
    mpz_mul(sig->sig_star, sig->sig_star, inv);
    mpz_mod(sig->sig_star, sig->sig_star, setup->q_EC);*/

    if(mpz_cmp(sig->sig_star, test) == 0){

        mpz_clear(test);
        return 0;

    } else {

        mpz_clear(test);
        return 1;
    }

}
void ZK_compute_Ts_Issuer(Manager_S* man_sec, Setup_SGM* setup, ZK_man *zk, ZK_man_private *zk_private) {
    mpz_t phi_n2;
    mpz_inits(zk->t1,zk->t2,zk_private->rho1, zk_private->rho2, zk_private->rho3,phi_n2,NULL);
    mpz_mul(phi_n2, man_sec->phi_n, setup->n);

    generate_r_from_group(&man_sec->phi_n_goth, &zk_private->rho1);
    generate_r_from_group(&phi_n2, &zk_private->rho2);
    generate_r_from_group(&man_sec->phi_n_goth, &zk_private->rho3);
    //generate_r_from_bitlenght(512, &zk_private->rho1);
    //generate_r_from_bitlenght(512, &zk_private->rho3);
    //compute t1
    mpz_t mid1,mid2;
    mpz_inits(mid1,mid2,NULL);
    mpz_powm(mid1, setup->h, zk_private->rho1, setup->n2);
    mpz_powm(zk->t1, setup->g, zk_private->rho2, setup->n2);
    mpz_mul(zk->t1, zk->t1, mid1);
    mpz_mod(zk->t1, zk->t1, setup->n2);
    mpz_clear(mid1);
    //now t1 is computed

    mpz_powm(mid2, setup->g_goth, zk_private->rho1, setup->n_goth);
    mpz_powm(zk->t2, setup->h_goth, zk_private->rho3, setup->n_goth);
    mpz_mul(zk->t2, zk->t2, mid2);
    mpz_mod(zk->t2, zk->t2, setup->n_goth);
    mpz_clears(mid2,phi_n2,NULL);
}

void generate_E_for_PK(Setup_SGM* setup, ZK_man *zk) {
    mpz_init(zk->e);
    //generate_r_from_group(&setup->n_goth, &zk->e);
    generate_r_from_bitlenght(1024, &zk->e);
}

void ZK_compute_Zs_Issuer(Manager_S* m_secret, Setup_SGM* setup, ZK_man* zk, ZK_man_private* zk_private) {
    mpz_inits(zk->z1, zk->z2, zk->z3, NULL);

    mpz_mul(zk->z1, zk->e, m_secret->sk_m);
    mpz_add(zk->z1, zk->z1, zk_private->rho1);
    mpz_mod(zk->z1,zk->z1,setup->n_goth);

    mpz_mul(zk->z2, zk->e, m_secret->r);
    mpz_add(zk->z2, zk->z2, zk_private->rho2);
    mpz_mod(zk->z2, zk->z2, setup->n2);

    mpz_mul(zk->z3, zk->e, m_secret->r_dash);
    mpz_add(zk->z3, zk->z3, zk_private->rho3);
    //mpz_mod(zk->z3, zk->z3, setup->n_goth);
}

void ZK_issuer_create(Manager_S* man_sec, Setup_SGM* setup, ZK_man* zk, ZK_man_private* zk_private) {
    mpz_t phi_n2;
    mpz_inits(zk->t1, zk->t2, zk_private->rho1, zk_private->rho2, zk_private->rho3, phi_n2, NULL);
    mpz_mul(phi_n2, man_sec->phi_n, setup->n);

    generate_r_from_group(&setup->n_goth, &zk_private->rho1);
    generate_r_from_group(&setup->n2, &zk_private->rho2);
    generate_r_from_group(&setup->n_goth, &zk_private->rho3);
    //generate_r_from_bitlenght(512, &zk_private->rho1);
    //generate_r_from_bitlenght(512, &zk_private->rho3);
    //compute t1
    mpz_t mid1, mid2;
    mpz_inits(mid1, mid2, NULL);
    mpz_powm(mid1, setup->h, zk_private->rho1, setup->n2);
    mpz_powm(zk->t1, setup->g, zk_private->rho2, setup->n2);
    mpz_mul(zk->t1, zk->t1, mid1);
    mpz_mod(zk->t1, zk->t1, setup->n2);
    mpz_clear(mid1);
    //now t1 is computed

    mpz_powm(mid2, setup->g_goth, zk_private->rho1, setup->n_goth);
    mpz_powm(zk->t2, setup->h_goth, zk_private->rho3, setup->n_goth);
    mpz_mul(zk->t2, zk->t2, mid2);
    mpz_mod(zk->t2, zk->t2, setup->n_goth);
    mpz_clears(mid2, phi_n2, NULL);

    mpz_init(zk->e);
    //now we hash to get e
    
    SHA256 eHash;
    uint8_t* placeholder = new uint8_t[32]();

    //we convert to uint8_t for hash
    size_t sz = mpz_sizeinbase(zk->t1, 2);
    size_t szt2 = mpz_sizeinbase(zk->t2, 2);
    //printf("size is %d \n", sz);

    int t1Count = (sz + 7) / 8;
    int t2Count = (szt2 + 7) / 8;
    uint8_t* t1_uint8 = (uint8_t*)malloc(t1Count);
    mpz_export(t1_uint8, NULL, 1, sizeof(t1_uint8[0]), 0, 0, zk->t1);
    
    uint8_t* t2_uint8 = (uint8_t*)malloc(t2Count);
    mpz_export(t2_uint8, NULL, 1, sizeof(t2_uint8[0]), 0, 0, zk->t2);

    for (int i = 0; i < t1Count / 2; i++)
        eHash.update(t1_uint8 + i * 2, 2);

    for (int i = 0; i < t2Count / 2; i++)
        eHash.update(t2_uint8 + i * 2, 2);

    placeholder = eHash.digest();
    free(t1_uint8);
    free(t2_uint8);
    mpz_import(zk->e, 32,1, sizeof(placeholder[0]), 0, 0, placeholder);

    //here we have how to import back
    /*mpz_t t12;
    mpz_init(t12);
    mpz_import(t12, (sz + 7) / 8, 1, sizeof(t1_uint8[0]), 0, 0, t1_uint8);
    if (mpz_cmp(zk->t1, t12) == 0)
        printf("fffffffffffffffff");*/
    
    mpz_inits(zk->z1, zk->z2, zk->z3, NULL);

    mpz_mul(zk->z1, zk->e, man_sec->sk_m);
    mpz_add(zk->z1, zk->z1, zk_private->rho1);
    mpz_mod(zk->z1, zk->z1, setup->n_goth);

    mpz_mul(zk->z2, zk->e, man_sec->r);
    mpz_add(zk->z2, zk->z2, zk_private->rho2);
    mpz_mod(zk->z2, zk->z2, setup->n2);

    mpz_mul(zk->z3, zk->e, man_sec->r_dash);
    mpz_add(zk->z3, zk->z3, zk_private->rho3);
    
}

bool check_issuer_zk(Setup_SGM* setup, ZK_man* zk, E_1* e_1)
{
    mpz_t hz1, gz2, frac,left,right,hn2;
    mpz_inits(hz1, gz2, frac, left,right,hn2,NULL);
    mpz_powm(hz1, setup->h, zk->z1, setup->n2);
    mpz_powm(gz2, setup->g, zk->z2, setup->n2);
    mpz_mul(left, hz1, gz2);
    mpz_mod(left, left, setup->n2);

    mpz_powm(hn2, setup->h, setup->n_half, setup->n2);
    mpz_invert(frac, hn2, setup->n2);
    mpz_mul(frac, e_1->e1, frac);
    mpz_mod(frac, frac, setup->n2);
    mpz_powm(right, frac, zk->e, setup->n2);
    mpz_mul(right, right, zk->t1);
    mpz_mod(right, right, setup->n2);

    if (mpz_cmp(left, right) != 0) 
    {
        mpz_clears(hz1, gz2, frac, left, right, hn2, NULL);
        return false;
    }
    

    mpz_t gz1, hz3, left2, right2;
    mpz_inits(gz1, hz3, left2, right2, NULL);
    mpz_powm(gz1, setup->g_goth, zk->z1,setup->n_goth);
    mpz_powm(hz3, setup->h_goth, zk->z3, setup->n_goth);
    mpz_mul(left2, gz1, hz3);
    mpz_mod(left2, left2, setup->n_goth);

    mpz_powm(right2, e_1->c_goth, zk->e, setup->n_goth);
    mpz_mul(right2, right2, zk->t2);
    mpz_mod(right2, right2, setup->n_goth);

    if (mpz_cmp(left2, right2) == 0) 
    {
        

        mpz_clears(gz1, hz3, left2, right2, NULL);
        mpz_clears(hz1, gz2, frac, left, right, hn2, NULL);
        return true;
    }
    else {
        mpz_clears(gz1, hz3, left2, right2, NULL);
        mpz_clears(hz1, gz2, frac, left, right, hn2, NULL);
        return false;
    }

    
}

bool check_issuer_proof_NI(Setup_SGM* setup, ZK_man* zk, E_1* e_1) {
    mpz_t hz1, gz2, frac, c1, hn2, einv;
    mpz_inits(hz1, gz2, frac, c1, hn2, einv, NULL);
    mpz_powm(hz1, setup->h, zk->z1, setup->n2);
    mpz_powm(gz2, setup->g, zk->z2, setup->n2);
    mpz_mul(c1, hz1, gz2);
    mpz_mod(c1, c1, setup->n2);

    mpz_powm(hn2, setup->h, setup->n_half, setup->n2);
    mpz_invert(frac, hn2, setup->n2);
    mpz_mul(frac, e_1->e1, frac);
    mpz_mod(frac, frac, setup->n2);

    //mpz_sub(einv, setup->n2, zk->e);
    //mpz_powm(frac, frac, einv, setup->n2);
    mpz_powm(frac, frac, zk->e, setup->n2);
    mpz_invert(frac, frac, setup->n2);
    mpz_mul(c1, c1, frac);
    mpz_mod(c1, c1, setup->n2);


    //now I have c1'

    mpz_t gz1, hz3, c2, ce, einv2;
    mpz_inits(gz1, hz3, c2, ce, einv2, NULL);
    mpz_powm(gz1, setup->g_goth, zk->z1, setup->n_goth);
    mpz_powm(hz3, setup->h_goth, zk->z3, setup->n_goth);
    mpz_mul(c2, gz1, hz3);
    mpz_mod(c2, c2, setup->n_goth);

    //mpz_sub(einv2, setup->n_goth, zk->e);
    //mpz_powm(ce, e_1->c_goth, einv2, setup->n_goth);
    mpz_powm(ce, e_1->c_goth, zk->e, setup->n_goth);
    mpz_invert(ce, ce, setup->n_goth);

    mpz_mul(c2, c2, ce);
    mpz_mod(c2, c2, setup->n_goth);

    //now we hash
    SHA256 eHash;
    uint8_t* placeholder = new uint8_t[32]();

    //we convert to uint8_t for hash
    size_t sz = mpz_sizeinbase(c1, 2);
    size_t szt2 = mpz_sizeinbase(c2, 2);

    int t1Count = (sz + 7) / 8;
    int t2Count = (szt2 + 7) / 8;
    uint8_t* t1_uint8 = (uint8_t*)malloc(t1Count);
    mpz_export(t1_uint8, NULL, 1, sizeof(t1_uint8[0]), 0, 0, c1);

    uint8_t* t2_uint8 = (uint8_t*)malloc(t2Count);
    mpz_export(t2_uint8, NULL, 1, sizeof(t2_uint8[0]), 0, 0, c2);

    for (int i = 0; i < t1Count / 2; i++)
        eHash.update(t1_uint8 + i * 2, 2);

    for (int i = 0; i < t2Count / 2; i++)
        eHash.update(t2_uint8 + i * 2, 2);

    placeholder = eHash.digest();
    free(t1_uint8);
    free(t2_uint8);

    mpz_t compareHash;
    mpz_init(compareHash);
    mpz_import(compareHash, 32, 1, sizeof(placeholder[0]), 0, 0, placeholder);
    if (mpz_cmp(compareHash, zk->e) == 0)
    {
        mpz_clears(hz1, gz2, frac, c1, hn2, einv, gz1, hz3, c2, ce, einv2, NULL);
        return true;
    }
    else
    {
        mpz_clears(hz1, gz2, frac, c1, hn2, einv, gz1, hz3, c2, ce, einv2, NULL);
        return false;
    }
       

}

void generate_ZK_user(Setup_SGM* setup, ZK_user* zk, Sender_S * user_sk, E_1* e1, E_2* e2, uECC_Curve curve) {

    mpz_t rhoS, rho1, rho2, rhoAph, rhoU, rhoGoth;
    mpz_inits(rhoS, rho1, rho2, rhoAph, rhoU, rhoGoth, NULL);
    //random rho generation
    generate_r_from_group(&setup->q_EC, &rhoS);
    generate_r_from_group(&setup->n_goth, &rhoGoth);
    generate_r_from_group(&setup->n_goth, &rhoAph);
    generate_r_from_group(&setup->n_goth, &rho1);
    generate_r_from_group(&setup->n2, &rho2);
    generate_r_from_group(&setup->n_goth, &rhoU);
    //lets compute pk_i for now

    
    const uECC_word_t* nCurve = uECC_curve_n(curve);
    const uECC_word_t* gCurve = uECC_curve_G(curve);
    const wordcount_t nativeCount = uECC_curve_num_words(curve);
    const wordcount_t nativeNCount = uECC_curve_num_n_words(curve);
    const wordcount_t byteCount = uECC_curve_num_bytes(curve);
    //calculation of pk_i
    zk->pk_i = new uECC_word_t[nativeNCount * 2]();
    uint8_t* sk_i_uint8 = (uint8_t*)malloc(byteCount * sizeof(uint8_t));
    mpz_export(sk_i_uint8, NULL, 1, sizeof(sk_i_uint8[0]), 0, 0, user_sk->sk_i);
    uECC_word_t* sk_i_native = new uECC_word_t[nativeNCount]();
    uECC_vli_bytesToNative(sk_i_native, sk_i_uint8, byteCount); //we convert ski to uecc
    uECC_point_mult(zk->pk_i, gCurve, sk_i_native, curve); //calculate pki

    mpz_t alpha, beta;
    mpz_inits(alpha, beta, NULL);
    mpz_powm(alpha, setup->h, setup->n_half,setup->n2);
    mpz_invert(alpha, alpha, setup->n2);//now we have h^n/2 in alpha
    mpz_mul(alpha, e1->e1, alpha);
    mpz_mod(alpha, alpha, setup->n2); //now we computed alpha
    mpz_powm(beta, setup->h, setup->q_EC,setup->n2);

    mpz_t c1, c2, c3,help;
    mpz_inits(c1, c2, c3,help, NULL);

    //computation of c1 in n^2
    mpz_powm(c1, alpha, rho1, setup->n2);
    mpz_powm(help, setup->h, rhoAph, setup->n2);
    mpz_mul(c1, c1, help);
    mpz_powm(help, beta, rho2, setup->n2);
    mpz_mul(c1, c1, help);
    mpz_powm(help, setup->g, rhoGoth, setup->n2);
    mpz_mul(c1, c1, help);
    mpz_mod(c1, c1, setup->n2);
    //computation of c2 in nGoth
    mpz_powm(c2, setup->g_goth, rhoS, setup->n_goth);
    mpz_powm(help, setup->h_goth, rhoGoth, setup->n_goth);
    mpz_mul(c2, c2, help);
    mpz_mod(c2, c2, setup->n_goth);
    //computation of c3 in goth
    mpz_powm(c3, e2->c2_goth, rho1, setup->n_goth);
    mpz_invert(help, setup->g_goth, setup->n_goth);
    mpz_powm(help, help, rhoAph, setup->n_goth);
    mpz_mul(c3, c3, help);
    mpz_powm(help, setup->h_goth, rhoU, setup->n_goth);

    //mpz_invert(help, help, setup->n_goth);//made this up

    mpz_mul(c3, c3, help);
    mpz_mod(c3, c3, setup->n_goth);
    //compute c4 on curve
    uECC_word_t *e4_point = new uECC_word_t[nativeNCount * 2]();
    uint8_t* rhoS_uint8 = (uint8_t*)malloc(byteCount * sizeof(uint8_t));
    mpz_export(rhoS_uint8, NULL, 1, sizeof(rhoS_uint8[0]), 0, 0, rhoS);
    uECC_word_t* rhoS_native = new uECC_word_t[nativeNCount]();//converting of rhoS to mciroECC
    uECC_vli_bytesToNative(rhoS_native, rhoS_uint8, byteCount);
    uECC_point_mult(e4_point, gCurve, rhoS_native, curve);
    //uint8_t* c4_uint8 = (uint8_t*)malloc(byteCount *2* sizeof(uint8_t));
    //uECC_vli_nativeToBytes(c4_uint8, byteCount * 2, e4_point); //c4 to uint we can hash that
    //zk->e4_point = e4_point;

    //these were just for check
    /*mpz_inits(zk->c1, zk->c2, zk->c3, NULL);
    mpz_set(zk->c1, c1);
    mpz_set(zk->c2, c2);
    mpz_set(zk->c3, c3);*/
    
    hashE(&zk->e, c1, c2, c3, e4_point, byteCount);

    mpz_t u;
    mpz_init(u);
    
    //mpz_sub(u, setup->n_goth, user_sk->r_bar); //I am not sure about this
    //this is kinda weird? as -r_bar as n-r_bar does not work? and it should imo, but the neg does work
    mpz_neg(u, user_sk->r_bar);
    mpz_mul(u, u, user_sk->r1);
    

    mpz_inits(zk->z1, zk->z2, zk->zs, zk->zu, zk->z_goth,zk->z_aph, NULL);
    mpz_mul(zk->zs, zk->e, user_sk->sk_i);
    mpz_add(zk->zs, zk->zs, rhoS);
    mpz_mul(zk->z1, zk->e, user_sk->r1);
    mpz_add(zk->z1, zk->z1, rho1);
    mpz_mul(zk->z2, zk->e, user_sk->r2);
    mpz_add(zk->z2, zk->z2, rho2);
    mpz_mul(zk->zu, zk->e, u);
    //ree



    mpz_add(zk->zu, zk->zu, rhoU); //modified here?
    mpz_mul(zk->z_goth, zk->e, user_sk->r_bar);
    mpz_add(zk->z_goth, zk->z_goth, rhoGoth);
    mpz_t sk_i_aph;
    mpz_init(sk_i_aph);
    mpz_mul(sk_i_aph, user_sk->sk_i, user_sk->r1);

    mpz_mul(zk->z_aph, zk->e, sk_i_aph);
    mpz_add(zk->z_aph, zk->z_aph, rhoAph);

    //this was just a check of the =1 eq to find out what was wrong
    /*mpz_t test_one, one, helpone;
    mpz_inits(test_one, one, helpone, NULL);
    mpz_set_ui(one, 1);
    mpz_powm(test_one, e2->c2_goth, user_sk->r1, setup->n_goth);
    mpz_invert(helpone, setup->g_goth, setup->n_goth);
    mpz_powm(helpone, helpone, sk_i_aph, setup->n_goth);
    mpz_mul(test_one, test_one, helpone);
    
    mpz_powm(helpone, setup->h_goth, u, setup->n_goth);
   
    //mpz_invert(helpone, helpone, setup->n_goth);

    mpz_mul(test_one, test_one, helpone);
    mpz_mod(test_one, test_one, setup->n_goth);
    if (mpz_cmp(test_one, one) == 0)
        printf("at least this shit works \n");*/
    
    

    mpz_clears(c1, c2, c3, help, alpha, beta, sk_i_aph, u,NULL);

}

bool check_PK_user(Setup_SGM* setup, ZK_user *zk, E_2* e2, E_1 * e1, uECC_Curve curve) {
    mpz_t alpha, beta;
    mpz_inits(alpha, beta, NULL);
    mpz_powm(alpha, setup->h, setup->n_half, setup->n2);
    mpz_invert(alpha, alpha, setup->n2);//now we have h^n/2 in alpha
    mpz_mul(alpha, e1->e1, alpha);
    mpz_mod(alpha, alpha, setup->n2); //now we computed alpha
    mpz_powm(beta, setup->h, setup->q_EC, setup->n2);

    mpz_t c1, c2, c3, help;
    mpz_inits(c1, c2, c3,help, NULL);

    mpz_powm(c1, alpha, zk->z1, setup->n2);
    mpz_powm(help, setup->h, zk->z_aph, setup->n2);
    mpz_mul(c1, c1, help);
    mpz_powm(help, beta, zk->z2, setup->n2);
    mpz_mul(c1, c1, help);
    mpz_powm(help, setup->g, zk->z_goth, setup->n2);
    mpz_mul(c1, c1, help);
    mpz_powm(help, setup->h, setup->n_half, setup->n2);
    mpz_invert(help, help, setup->n2);
    mpz_mul(help, e2->e2, help);
    mpz_mod(help, help, setup->n2);
    mpz_powm(help, help, zk->e, setup->n2);
    mpz_invert(help, help, setup->n2);
    mpz_mul(c1, c1, help);
    mpz_mod(c1, c1, setup->n2);
    //if (mpz_cmp(c1, zk->c1) == 0)// we will remove this check later
        //printf("c1 works! \n");

    mpz_powm(c2, setup->g_goth, zk->zs, setup->n_goth);
    mpz_powm(help, setup->h_goth, zk->z_goth, setup->n_goth);
    mpz_mul(c2, c2, help);
    mpz_powm(help, e2->c2_goth, zk->e, setup->n_goth);
    mpz_invert(help, help, setup->n_goth);
    mpz_mul(c2, c2, help);
    mpz_mod(c2, c2, setup->n_goth);
    //if (mpz_cmp(c2, zk->c2) == 0)// we will remove this check later
        //printf("c2 works! \n");

    mpz_powm(c3, e2->c2_goth, zk->z1, setup->n_goth);
    mpz_invert(help, setup->g_goth, setup->n_goth);
    mpz_powm(help, help, zk->z_aph, setup->n_goth);//is this right?
    mpz_mul(c3,c3,help);

    mpz_powm(help, setup->h_goth, zk->zu, setup->n_goth);
    //mpz_invert(help,help,setup->n_goth);//i made this shit up

    mpz_mul(c3,c3,help);
    mpz_mod(c3, c3, setup->n_goth);
    //if (mpz_cmp(c3, zk->c3) == 0)// we will remove this check later
        //printf("c3 works! \n");
    
    const uECC_word_t* nCurve = uECC_curve_n(curve);
    const uECC_word_t* gCurve = uECC_curve_G(curve);
    const wordcount_t nativeCount = uECC_curve_num_words(curve);
    const wordcount_t nativeNCount = uECC_curve_num_n_words(curve);
    const wordcount_t byteCount = uECC_curve_num_bytes(curve);

    uECC_word_t* c4_point = new uECC_word_t[nativeNCount * 2]();
    uECC_word_t* help_point = new uECC_word_t[nativeNCount * 2]();

    uECC_word_t* zs_uecc = new uECC_word_t[nativeNCount]();

    
    mpz_mod(zk->zs, zk->zs, setup->q_EC); //not sure
    uint8_t* zs_bytes = (uint8_t*)malloc(byteCount * sizeof(uint8_t));
    mpz_export(zs_bytes, NULL, 1, sizeof(zs_bytes[0]), 0, 0, zk->zs);
    uECC_vli_bytesToNative(zs_uecc, zs_bytes, byteCount);

    
    mpz_t eModed;
    mpz_init(eModed);
    mpz_mod(eModed, zk->e, setup->q_EC);
    //mpz_neg(eModed, eModed);
    //mpz_mod(eModed, zk->e, setup->q_EC);
    mpz_sub(eModed, setup->q_EC, eModed);
    
    uECC_word_t* e_in_ecc = new uECC_word_t[nativeNCount]();
    uint8_t* e_bytes = (uint8_t*)malloc(byteCount * sizeof(uint8_t));
    mpz_export(e_bytes, NULL, 1, sizeof(e_bytes[0]), 0, 0, eModed);
    uECC_vli_bytesToNative(e_in_ecc, e_bytes, byteCount);
   
    uECC_point_mult(c4_point, gCurve, zs_uecc, curve);
    uECC_point_mult(help_point, zk->pk_i, e_in_ecc, curve);
    //uECC_point_add(zk->e4_point, help_point, zk->e4_point, curve); //modded
    uECC_point_add(c4_point, help_point, c4_point, curve);
    //if (uECC_vli_cmp(c4_point, zk->e4_point, nativeCount) == 0)
        //printf("eeeeeeeeee4\n");

    free(zs_bytes);
    free(e_bytes);

    mpz_t eCheck;
    mpz_init(eCheck);
    hashE(&eCheck, c1, c2, c3, c4_point, byteCount);
    if (mpz_cmp(eCheck, zk->e) == 0) {
        printf("the user proof is valid \n");
        mpz_clears(alpha, beta, c1, c2, c3, help, eModed, eCheck,NULL);
        return true;
    }
    else {
        printf("the user proof was not checked sucesfuly\n");
        mpz_clears(alpha, beta, c1, c2, c3, help, eModed, eCheck, NULL);
        return false;
    }

    
}

void hashE(mpz_t* e, mpz_t c1, mpz_t c2, mpz_t c3, uECC_word_t* c4, const wordcount_t byteCount) {
    SHA256 eHash;
    uint8_t* placeholder = new uint8_t[32]();

    uint8_t* c4_uint8 = (uint8_t*)malloc(byteCount * 2 * sizeof(uint8_t));
    uECC_vli_nativeToBytes(c4_uint8, byteCount * 2, c4); //c4 to uint we can hash that

    size_t sz_c1 = mpz_sizeinbase(c1, 2);
    size_t sz_c2 = mpz_sizeinbase(c2, 2);
    size_t sz_c3 = mpz_sizeinbase(c3, 2);
    int c1Count = (sz_c1 + 7) / 8;
    int c2Count = (sz_c2 + 7) / 8;
    int c3Count = (sz_c3 + 7) / 8;
    uint8_t* c1_uint8 = (uint8_t*)malloc(c1Count * sizeof(uint8_t));
    mpz_export(c1_uint8, NULL, 1, sizeof(c1_uint8[0]), 0, 0, c1);
    uint8_t* c2_uint8 = (uint8_t*)malloc(c2Count * sizeof(uint8_t));
    mpz_export(c2_uint8, NULL, 1, sizeof(c2_uint8[0]), 0, 0, c2);
    uint8_t* c3_uint8 = (uint8_t*)malloc(c3Count * sizeof(uint8_t));
    mpz_export(c3_uint8, NULL, 1, sizeof(c3_uint8[0]), 0, 0, c3);
    for (int i = 0; i < c1Count / 2; i++)
        eHash.update(c1_uint8 + i * 2, 2);
    for (int i = 0; i < c2Count / 2; i++)
        eHash.update(c2_uint8 + i * 2, 2);
    for (int i = 0; i < c3Count / 2; i++)
        eHash.update(c3_uint8 + i * 2, 2);
    for (int i = 0; i < (byteCount * 2) / 2; i++)
        eHash.update(c4_uint8 + i * 2, 2);

    placeholder = eHash.digest();
    free(c1_uint8);
    free(c2_uint8);
    free(c3_uint8);
    free(c4_uint8);

    mpz_init(*e);
    mpz_import(*e, 32, 1, sizeof(placeholder[0]), 0, 0, placeholder);
}

int JSON_serialize_Setup_par(Setup_SGM* setup){

    FILE* fp;
    fp = fopen("par.json", "w+");

    if(fp == NULL){
        return 1;
    }

    fprintf(fp, SETUP_JSON_OUT, mpz_get_str(NULL, 16, setup->n), mpz_get_str(NULL, 16, setup->g), 
            mpz_get_str(NULL, 16, setup->h), mpz_get_str(NULL, 16, setup->n_goth), mpz_get_str(NULL, 16, setup->g_goth), 
            mpz_get_str(NULL, 16, setup->h_goth), mpz_get_str(NULL, 16, setup->q_EC));
    
    fclose(fp);

    return 0;
}

int JSON_serialize_e1(E_1* e1){

    FILE* fp;
    fp = fopen("e1.json", "w+");

    if(fp == NULL){
        return 1;
    }

    fprintf(fp, E1_JSON_OUT, mpz_get_str(NULL, 16, e1->e1), mpz_get_str(NULL, 16, e1->c_goth));
    
    fclose(fp);
    
    return 0;
}

int JSON_serialize_e2(E_2* e2){

    FILE* fp;
    fp = fopen("e2.json", "w+");

    if(fp == NULL){
        return 1;
    }

    fprintf(fp, E2_JSON_OUT, mpz_get_str(NULL, 16, e2->e2), mpz_get_str(NULL, 16, e2->c2_goth));
    
    fclose(fp);
    return 0;
}

int JSON_serialize_sig_star(Sig_star* sig_star){

    FILE* fp;
    fp = fopen("sig_star.json", "w+");

    if(fp == NULL){
        return 1;
    }

    fprintf(fp, SIG_STAR_JSON_OUT, mpz_get_str(NULL, 16, sig_star->sig_star));
    
    fclose(fp);
    return 0;
}


int JSON_deserialize_Setup_par(Setup_SGM* setup){

    char n[6000];
    char g[10000];
    char h[6000];
    char n_g[6000];
    char h_g[6000];
    char g_g[6000];
    char q_EC[500];

    FILE* fp;
    fp = fopen("par.json", "r");

    if(fp == NULL){
        return 1;
    }

    fscanf(fp, SETUP_JSON_IN, n, g, h, n_g, h_g, g_g, q_EC);

    mpz_init_set_str(setup->n, n, 16);
    mpz_init_set_str(setup->g, g, 16);
    mpz_init_set_str(setup->h, h, 16);
    mpz_init_set_str(setup->n_goth, n_g, 16);
    mpz_init_set_str(setup->g_goth, h_g, 16);
    mpz_init_set_str(setup->h_goth, g_g, 16);
    mpz_init_set_str(setup->q_EC, q_EC, 16);

    mpz_init(setup->n2);
    mpz_mul(setup->n2, setup->n, setup->n);
    
    mpz_t two;
    mpz_init(two);
    mpz_set_ui(two, 2);

    mpz_init(setup->n_half);
    mpz_fdiv_q(setup->n_half, setup->n, two);

    fclose(fp);
    return 0;

}


int JSON_deserialize_e1(E_1* e1){

    char e1c[6000];
    char c_g[6000];
    FILE* fp;
    fp = fopen("e1.json", "r");

    if(fp == NULL){
        return 1;
    }


    fscanf(fp, E1_JSON_IN, e1c, c_g);

    mpz_init_set_str(e1->e1, e1c, 16);
    mpz_init_set_str(e1->c_goth, c_g, 16);

    fclose(fp);
    return 0;

}

int JSON_deserialize_e2(E_2* e2){

    char e2c[6000];
    char c2_g[6000];
    FILE* fp;
    fp = fopen("e2.json", "r");

    if(fp == NULL){
        return 1;
    }


    fscanf(fp, E2_JSON_IN, e2c, c2_g);

    mpz_init_set_str(e2->e2, e2c, 16);
    mpz_init_set_str(e2->c2_goth, c2_g, 16);

    fclose(fp);
    return 0;

}

int JSON_deserialize_sig_star(Sig_star* sig_star){

    char sig[6000];
    FILE* fp;
    fp = fopen("sig_star.json", "r");

    if(fp == NULL){
        return 1;
    }


    fscanf(fp, SIG_STAR_JSON_IN, sig);

    mpz_init_set_str(sig_star->sig_star, sig, 16);

    fclose(fp);
    return 0;

}



