#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include "nizkpk_join.hpp"
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/types.h>
#include <openssl/crypto.h>

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
    mpz_powm(e22, setup->h_goth, s_secret->sk_i, setup->n_goth);
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
    mpz_powm(e22, setup->h_goth, s_secret->sk_i, setup->n_goth);
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
    mpz_clears(hz1, gz2, frac, left, right, hn2, NULL);

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
        return true;
    }
    else {
        mpz_clears(gz1, hz3, left2, right2, NULL);
        return false;
    }

    
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



