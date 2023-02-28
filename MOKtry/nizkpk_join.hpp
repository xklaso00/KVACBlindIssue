#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <uECC_Parameters_t.hpp>
#include <uECC_List_t.hpp>
#include <uECC_vli.h>
typedef struct
{
    mpz_t q_EC;   

	mpz_t n;
    mpz_t n2;
    mpz_t n_half;
	mpz_t h;
    mpz_t g;

	mpz_t n_goth;
	mpz_t g_goth;
	mpz_t h_goth;

    //mpz_t pk_s;


} Setup_SGM;


typedef struct
{
    mpz_t sk_m;

    mpz_t phi_n;
    mpz_t phi_n_goth;

    mpz_t r;
    mpz_t r_dash;


} Manager_S;



typedef struct
{
    mpz_t t1;
    mpz_t t2;
    mpz_t z1;
    mpz_t z2;
    mpz_t z3;
    mpz_t e;
} ZK_man;

typedef struct
{
    mpz_t zs;
    mpz_t z1;
    mpz_t z2;
    mpz_t zu;
    mpz_t z_goth;
    mpz_t z_aph;
    mpz_t e;
    uECC_word_t *pk_i;
    

}ZK_user;

typedef struct
{
    mpz_t rho1;
    mpz_t rho2;
    mpz_t rho3;

} ZK_man_private;

typedef struct
{
    mpz_t sk_i;

    mpz_t r1;
    mpz_t r2;
    mpz_t r_bar;

} Sender_S;


typedef struct
{
    mpz_t e1;

    mpz_t c_goth;


} E_1;

typedef struct
{
    mpz_t e2;

    mpz_t c2_goth;
    //mpz_t pk_i;


} E_2;

typedef struct
{
    mpz_t sig_star;

} Sig_star;

void generate_r_from_group(mpz_t* mod, mpz_t* r);

void generate_r_from_bitlenght(size_t length, mpz_t* r);

void generate_RSA_SSL(mpz_t* p, mpz_t* q, mpz_t* n, size_t size);

void generate_nizkpk_setup(Setup_SGM* setup, Manager_S* m_secret, uint8_t q_EC[], uint8_t manKey[], int byteCount);

E_1 generate_e1(Setup_SGM* setup, Manager_S* m_secret);

E_2 generate_e2(Setup_SGM* setup, Sender_S* s_secret, E_1* e1, uint8_t client_sec[], int byteCount);

Sig_star decrypt_e2(Setup_SGM* setup, Manager_S* m_secret, E_2* e2);

int verify_sig(Sig_star* sig, Manager_S* m_secret, Sender_S* s_secret, Setup_SGM* setup);

void generate_E_for_PK(Setup_SGM* setup, ZK_man* zk);

void ZK_compute_Zs_Issuer(Manager_S* m_secret, Setup_SGM* setup, ZK_man* zk, ZK_man_private* zk_private);

bool check_issuer_zk(Setup_SGM* setup, ZK_man* zk, E_1* e_1);

void ZK_compute_Ts_Issuer(Manager_S* man_s, Setup_SGM* setup, ZK_man* zk, ZK_man_private* zk_private);

void ZK_issuer_create(Manager_S* man_sec, Setup_SGM* setup, ZK_man* zk, ZK_man_private* zk_private);

bool check_issuer_proof_NI(Setup_SGM* setup, ZK_man* zk, E_1* e_1);

void hashE(mpz_t* e, mpz_t c1, mpz_t c2, mpz_t c3, uECC_word_t* c4, const wordcount_t byteCount);

void generate_ZK_user(Setup_SGM* setup, ZK_user* zk, Sender_S* user_sk, E_1* e1, E_2* e2, uECC_Curve curve);

bool check_PK_user(Setup_SGM* setup, ZK_user* zk, E_2* e2, E_1* e1, uECC_Curve curve);

int JSON_serialize_Setup_par(Setup_SGM* setup);

int JSON_serialize_e1(E_1* e1);

int JSON_serialize_e2(E_2* e2);

int JSON_serialize_sig_star(Sig_star* sig_star);

int JSON_deserialize_Setup_par(Setup_SGM* setup);

int JSON_deserialize_e1(E_1* e1);

int JSON_deserialize_e2(E_2* e2);

int JSON_deserialize_sig_star(Sig_star* sig_star);
