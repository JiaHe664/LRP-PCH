#include "relic/relic.h"
#include "pari/pari.h"
#include "../include/types.h"
#include "../include/utils.h"
#include "../include/performance.h"
#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define LOOP_TIMES 10;

int RP_setUp(RP_t rp_params)
{
	int result_status = RLC_OK;

    if (generate_cl_params(rp_params->gp) != RLC_OK) {
      RLC_THROW(ERR_CAUGHT);
    }

	RLC_TRY {
	    // Compute CL encryption secret/public key pair for the tumbler.
		rp_params->td->sk = randomi(rp_params->gp->bound);
        // printf("\nSize of sk : %d B\n",sizeof(*(rp_params->td->sk)));
        // printf("\nSize of GEN : %d B\n",sizeof(*(rp_params->td->sk)));
		rp_params->pk->pk = nupow(rp_params->gp->g_q, rp_params->td->sk, NULL);
        // printf("\n####################### cl_sk #######################\n");
        // printf(GENtostr(rp_params->td->sk));
        // printf("\n####################### cl_sk #######################\n");
        // printf("\n####################### cl_pk #######################\n");
        // printf(GENtostr(rp_params->pk->pk));
        // printf("\n####################### cl_pk #######################\n");        
        // printf("\nRP params init sucessfully!\n");
    } RLC_CATCH_ANY {
		result_status = RLC_ERR;
	} RLC_FINALLY {
	}

	return result_status;

}

int RP_gen(puzzle_t puzzle,const RP_t rp_params){
    if (puzzle == NULL) {
        RLC_THROW(ERR_NO_VALID);
    }

    int result_status = RLC_OK;

    bn_t q,alpha;
    bn_null(q);
    bn_null(alpha);
    RLC_TRY {
        bn_new(q);
        bn_new(alpha);

        ec_curve_get_ord(q);
        bn_rand_mod(alpha, q);
        ec_mul_gen(puzzle->g_to_the_alpha, alpha);

        const unsigned alpha_str_len = bn_size_str(alpha, 10);
        char alpha_str[alpha_str_len];
        bn_write_str(alpha_str, alpha_str_len, alpha, 10);
        // printf("\n####################### g_to_the_alpha #######################\n");
        // printf(puzzle->g_to_the_alpha);
        // printf("\n####################### plain of alpha #######################\n");
        // printf("%s",alpha_str);
        GEN plain_alpha = strtoi(alpha_str);
        if (cl_enc(puzzle->ctx_alpha, plain_alpha, rp_params->pk, rp_params->gp) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
        }
        // printf("\n####################### cipher of alpha #######################\n");
        // printf("\n####################### c1 #######################\n");
        // printf(GENtostr(puzzle->ctx_alpha->c1));
        // printf("\n####################### c2 #######################\n");
        // printf(GENtostr(puzzle->ctx_alpha->c2));
        // printf("\nPuzzle generates sucessfully!\n");
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        bn_free(q);
        bn_free(alpha);
    }

    return result_status;

}

int RP_solve(const RP_t rp_params,const puzzle_t puzzle){
    if (rp_params == NULL || puzzle == NULL) {
        RLC_THROW(ERR_NO_VALID);
    }

    int result_status = RLC_OK;

    bn_t alpha;
    bn_null(alpha);

    RLC_TRY {
        bn_new(alpha);

        // Decrypt the ciphertext.
        GEN _alpha;
        if (cl_dec(&_alpha, puzzle->ctx_alpha, rp_params->td, rp_params->gp) != RLC_OK) {
        RLC_THROW(ERR_CAUGHT);
        }
        bn_read_str(alpha, GENtostr(_alpha), strlen(GENtostr(_alpha)), 10);

        const unsigned alpha_str_len = bn_size_str(alpha, 10);
        char alpha_str[alpha_str_len];
        bn_write_str(alpha_str, alpha_str_len, alpha, 10);
        // printf("\n####################### plain of alpha #######################\n");
        // printf("%s",alpha_str);
        // printf("\nPuzzle solves sucessfully!\n");
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        bn_free(alpha);
    }

    return result_status;
}

int RP_rand(puzzle_t puzzle_rand,const RP_pp_t rp_pp,const puzzle_t puzzle){
    if (rp_pp == NULL || puzzle == NULL) {
        RLC_THROW(ERR_NO_VALID);
    }
    
    int result_status = RLC_OK;

    bn_t q,beta;
    // printf("\n Size of beta: %d B\n",sizeof(*beta));

    bn_null(q);
    bn_null(beta);

    RLC_TRY {
        bn_new(q);
        bn_new(beta);
        ec_curve_get_ord(q);

        // Randomize the promise challenge.
        GEN beta_prime = randomi(rp_pp->gp->bound);
        // printf("\n--------Size of gp : %d B\n",sizeof(cl_params_st));
        bn_read_str(beta, GENtostr(beta_prime), strlen(GENtostr(beta_prime)), 10);
        bn_mod(beta, beta, q);

        ec_mul(puzzle_rand->g_to_the_alpha, puzzle->g_to_the_alpha, beta);
        ec_norm(puzzle_rand->g_to_the_alpha, puzzle_rand->g_to_the_alpha);

        // Homomorphically randomize the challenge ciphertext.
        const unsigned beta_str_len = bn_size_str(beta, 10);
        char beta_str[beta_str_len];
        bn_write_str(beta_str, beta_str_len, beta, 10);

        GEN plain_beta = strtoi(beta_str);
        puzzle_rand->ctx_alpha->c1 = nupow(puzzle->ctx_alpha->c1, plain_beta, NULL);
        puzzle_rand->ctx_alpha->c2 = nupow(puzzle->ctx_alpha->c2, plain_beta, NULL);
        // printf("\n####################### g_to_the_alpha_times_beta #######################\n");
        // printf(puzzle_rand->g_to_the_alpha);
        // printf("\n####################### plain of beta #######################\n");
        // printf("%s",beta_str);
        // printf("\n####################### cipher of alpha_times_beta #######################\n");
        // printf("\n####################### c1 #######################\n");
        // printf(GENtostr(puzzle_rand->ctx_alpha->c1));
        // printf("\n####################### c2 #######################\n");
        // printf(GENtostr(puzzle_rand->ctx_alpha->c2));
        // printf("\nPuzzle randoms sucessfully!\n");
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        bn_free(beta);
        bn_free(q);
    }

    return result_status;
}


int main(void){
    clock_t start_time;
    clock_t finish_time;
    float total_time=0,run_time;
    init();
    int result_status = RLC_OK;
    // RP_t rp_params;
    // RP_pp_t rp_pp;
    // puzzle_t puzzle,puzzle_rand;
    // RP_null(rp_params);
    // RP_pp_null(rp_pp);
    // puzzle_null(puzzle);
    // puzzle_null(puzzle_rand);    
    // RLC_TRY {
    //     RP_new(rp_params);
    //     RP_pp_new(rp_pp);
    //     // RP_setUp(rp_params);
    //     printf("\n####################### runtime of RP_setUp #######################\n");
    //     for(int i=1;i<=LOOP_TIMES){
    //         start_time=clock();
    //         RP_setUp(rp_params);
    //         finish_time=clock();
    //         run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
    //         printf("%f s\t",run_time);
    //         i++;
    //     }
    //     rp_pp->gp=rp_params->gp;
    //     rp_pp->pk=rp_params->pk;
    //     puzzle_new(puzzle);
    //     // RP_gen(puzzle,rp_params);
    //     // total_time=0;
    //     printf("\n####################### runtime of RP_gen #######################\n");
    //     for(int i=1;i<=LOOP_TIMES){
    //         start_time=clock();
    //         RP_gen(puzzle,rp_params);
    //         finish_time=clock();
    //         run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
    //         printf("%f s\t",run_time);
    //         i++;
    //     }
    //     printf("\n####################### runtime of RP_solve #######################\n");
    //     // RP_solve(rp_params,puzzle);
    //     for(int i=1;i<=LOOP_TIMES){
    //         start_time=clock();
    //         RP_solve(rp_params,puzzle);
    //         finish_time=clock();
    //         run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
    //         printf("%f s\t",run_time);
    //         i++;
    //     }
    //     printf("\n####################### runtime of RP_rand #######################\n");
    //     puzzle_new(puzzle_rand);   
    //     // RP_rand(puzzle_rand,rp_pp,puzzle);
    //     for(int i=1;i<=LOOP_TIMES){
    //         start_time=clock();
    //         RP_rand(puzzle_rand,rp_pp,puzzle);
    //         finish_time=clock();
    //         run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
    //         printf("%f s\t",run_time);
    //         i++;
    //     }
    //     printf("program exit\n");

    // the variables of zk_cldl_prove
    zk_proof_cldl_t pi_cldl;
    zk_proof_cldl_null(pi_cldl);
    bn_t alpha;
    bn_null(alpha);
    bn_t q;
    bn_null(q);
    cl_ciphertext_t ctx_alpha;
    cl_ciphertext_null(ctx_alpha);
    cl_params_t cl_params;
    cl_params_null(cl_params);
    cl_secret_key_t tumbler_cl_sk;
    cl_public_key_t tumbler_cl_pk;
    cl_secret_key_null(tumbler_cl_sk);
    cl_public_key_null(tumbler_cl_pk);
    ec_t g_to_the_alpha;
    ec_null(g_to_the_alpha);

    // the variables of adaptor_schnorr_sign
    schnorr_signature_t sigma_tr;
    schnorr_signature_null(sigma_tr);
    ec_secret_key_t tumbler_ec_sk;
    ec_public_key_t tumbler_ec_pk;
    ec_secret_key_null(tumbler_ec_sk);
    ec_public_key_null(tumbler_ec_pk);

    // the variables of pedersen_commit
	bn_t pc_q, x, y, tid;
    ps_secret_key_t tumbler_ps_sk;
    ps_public_key_t tumbler_ps_pk;
    pedersen_com_t pcom;
    pedersen_decom_t pdecom;
    pedersen_com_null(pcom);
    pedersen_decom_null(pdecom);
	bn_null(pc_q);
	bn_null(x);
	bn_null(y);
	bn_null(tid);
    ps_secret_key_null(tumbler_ps_sk);
    ps_public_key_null(tumbler_ps_pk);

    // the variables of zk_pedersen_com_prove
    pedersen_com_zk_proof_t com_zk_proof;
    pedersen_com_zk_proof_null(com_zk_proof);

    // the variables of ps_blind_sign
    ps_signature_t sigma_prime;
    ps_signature_null(sigma_prime);

    RLC_TRY{

        // zk_cldl_prove
        bn_new(q);
        bn_new(alpha);
        cl_ciphertext_new(ctx_alpha);
        cl_params_new(cl_params);
        cl_secret_key_new(tumbler_cl_sk);
        cl_public_key_new(tumbler_cl_pk);
        zk_proof_cldl_new(pi_cldl);
        ec_curve_get_ord(q);
        printf("\nSize of bn_t : %d B\n",sizeof(q));
        printf("\nSize of tx : %d B\n",sizeof(tx));
        bn_rand_mod(alpha, q);
        // compute g_to_the_alpha
        ec_new(g_to_the_alpha);     
        ec_mul_gen(g_to_the_alpha, alpha);
        const unsigned alpha_str_len = bn_size_str(alpha, 10);
        char alpha_str[alpha_str_len];
        bn_write_str(alpha_str, alpha_str_len, alpha, 10);

        if (generate_cl_params(cl_params) != RLC_OK) {
            RLC_THROW(ERR_CAUGHT);
        }

		// Compute CL encryption secret/public key pair for the tumbler.
		tumbler_cl_sk->sk = randomi(cl_params->bound);
		tumbler_cl_pk->pk = nupow(cl_params->g_q, tumbler_cl_sk->sk, NULL);

        GEN plain_alpha = strtoi(alpha_str);
        if (cl_enc(ctx_alpha, plain_alpha, tumbler_cl_pk, cl_params) != RLC_OK) {
            RLC_THROW(ERR_CAUGHT);
        }
        printf("\n####################### runtime of zk_cldl_prove #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (zk_cldl_prove(pi_cldl, plain_alpha, ctx_alpha, tumbler_cl_pk, cl_params) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }


        // zk_cldl_verify
        printf("\n####################### runtime of zk_cldl_verify #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (zk_cldl_verify(pi_cldl, g_to_the_alpha, ctx_alpha, tumbler_cl_pk, cl_params) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }

        // adaptor_schnorr_sign
        schnorr_signature_new(sigma_tr);
        ec_secret_key_new(tumbler_ec_sk);
        ec_public_key_new(tumbler_ec_pk);
        // Compute EC secret/public key pairs.
        bn_rand_mod(tumbler_ec_sk->sk, q);
        ec_mul_gen(tumbler_ec_pk->pk, tumbler_ec_sk->sk);


        printf("\n####################### runtime of adaptor_schnorr_sign #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (adaptor_schnorr_sign(sigma_tr, tx, sizeof(tx), g_to_the_alpha, tumbler_ec_sk) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }

        // adaptor_schnorr_preverify
        printf("\n####################### runtime of adaptor_schnorr_preverify #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (adaptor_schnorr_preverify(sigma_tr, tx, sizeof(tx), g_to_the_alpha, tumbler_ec_pk) != 1) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }

        // pedersen_commit
		bn_new(pc_q);
		bn_new(x);
		bn_new(y);
		bn_new(tid);
        ps_secret_key_new(tumbler_ps_sk);
        ps_public_key_new(tumbler_ps_pk);
        pedersen_com_new(pcom);
        pedersen_decom_new(pdecom);

		// Compute PS secret/public key pair for the tumbler.
		pc_get_ord(pc_q);
		bn_rand_mod(x, pc_q);
		bn_rand_mod(y, pc_q);

		g1_mul_gen(tumbler_ps_sk->X_1, x);
		g1_mul_gen(tumbler_ps_pk->Y_1, y);
		g2_mul_gen(tumbler_ps_pk->X_2, x);
		g2_mul_gen(tumbler_ps_pk->Y_2, y);

        bn_rand_mod(tid, q);

        printf("\n####################### runtime of pedersen_commit #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (pedersen_commit(pcom, pdecom, tumbler_ps_pk->Y_1, tid) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }
        printf("\nSize of pcom: %d B\n",sizeof(pcom->c));


        // zk_pedersen_com_prove
        pedersen_com_zk_proof_new(com_zk_proof);

        printf("\n####################### runtime of zk_pedersen_com_prove #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (zk_pedersen_com_prove(com_zk_proof, tumbler_ps_pk->Y_1, pcom, pdecom) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }

        // zk_pedersen_com_verify
        printf("\n####################### runtime of zk_pedersen_com_verify #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (zk_pedersen_com_verify(com_zk_proof, tumbler_ps_pk->Y_1, pcom) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }


        // ps_blind_sign
        ps_signature_new(sigma_prime);

        printf("\n####################### runtime of ps_blind_sign #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (ps_blind_sign(sigma_prime, pcom, tumbler_ps_sk) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }

        // ps_unblind
        printf("\n####################### runtime of ps_unblind #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (ps_unblind(sigma_prime, pdecom) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }

        // ps_verify
        printf("\n####################### runtime of ps_verify #######################\n");
        for(int i=1;i<=LOOP_TIMES){
            start_time=clock();
            if (ps_verify(sigma_prime, tid, tumbler_ps_pk) != RLC_OK) {
                RLC_THROW(ERR_CAUGHT);
            }
            finish_time=clock();
            run_time=(float)(finish_time-start_time)/CLOCKS_PER_SEC;
            printf("%f s\t",run_time);
            i++;
        }

        
    } RLC_CATCH_ANY {
        result_status = RLC_ERR;
    } RLC_FINALLY {
        schnorr_signature_free(sigma_tr);
        ec_secret_key_free(tumbler_ec_sk);
        ec_public_key_free(tumbler_ec_pk);

		bn_free(pc_q);
		bn_free(x);
		bn_free(y);
		bn_free(tid);
        ps_secret_key_free(tumbler_ps_sk);
        ps_public_key_free(tumbler_ps_pk);
        pedersen_com_free(pcom);
        pedersen_decom_free(pdecom);

        ps_signature_free(sigma_prime);

        pedersen_com_zk_proof_free(com_zk_proof);

        bn_free(alpha);
        bn_free(q);
        cl_ciphertext_free(ctx_alpha);
        cl_params_free(cl_params);
        cl_secret_key_free(tumbler_cl_sk);
        cl_public_key_free(tumbler_cl_pk);
        zk_proof_cldl_free(pi_cldl);
        ec_free(g_to_the_alpha);
        // RP_pp_free(rp_pp);
        // puzzle_free(puzzle);
        // puzzle_free(puzzle_rand);
    }
    clean();
    return result_status;
}