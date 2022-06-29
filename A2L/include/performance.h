// A2L协议中tumbler所需的数据和操作声明

#ifndef A2L_SCHNORR_INCLUDE_RP
#define A2L_SCHNORR_INCLUDE_RP

#include <stddef.h>
#include <string.h>
#include "relic/relic.h"
#include "types.h"

typedef struct{
    cl_params_t gp;   // Castagnos-Laguillaumie (CL)同态加密方案中的公开参数
    cl_public_key_t pk;   // Castagnos-Laguillaumie (CL)同态加密方案中的公钥
}RP_pp_st;    // Random Puzzle方案中的公开参数

typedef RP_pp_st *RP_pp_t;

#define RP_pp_null(rp_pp) rp_pp=NULL;   // 用于RP_pp的初始化

// 为RP_pp开辟存储空间
#define RP_pp_new(rp_pp)                                     \
  do {                                                        \
    rp_pp = malloc(sizeof(RP_pp_st));                        \
    if (rp_pp == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    cl_public_key_new((rp_pp)->pk);                       \
    cl_params_new((rp_pp)->gp);                           \
  } while (0)

// 回收RP_pp的存储空间
#define RP_pp_free(rp_pp)                                    \
  do {                                                    \
    cl_public_key_free((rp_pp)->pk);                      \
    cl_params_free((rp_pp)->gp);                          \
    free(rp_pp);                                          \
    rp_pp = NULL;                                         \
  } while (0)

typedef struct {
    cl_params_t gp;
    cl_public_key_t pk;
    cl_secret_key_t td;   // Castagnos-Laguillaumie (CL)同态加密方案中的私钥
}RP_st;     // Random Puzzle方案中的系统参数

typedef RP_st *RP_t;

#define RP_null(rp_params) rp_params=NULL;

#define RP_new(rp_params)                                     \
  do {                                                    \
    rp_params = malloc(sizeof(RP_st));                        \
    if (rp_params == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    cl_secret_key_new((rp_params)->td);                       \
    cl_public_key_new((rp_params)->pk);                       \
    cl_params_new((rp_params)->gp);                           \
  } while (0)

#define RP_free(rp_params)                                    \
  do {                                                    \
    cl_secret_key_free((rp_params)->td);                      \
    cl_public_key_free((rp_params)->pk);                      \
    cl_params_free((rp_params)->gp);                          \
    free(rp_params);                                          \
    rp_params = NULL;                                         \
  } while (0)

typedef struct {
    ec_t g_to_the_alpha;    // g^alpha，即A
    cl_ciphertext_t ctx_alpha;    // alpha的密文（Castagnos-Laguillaumie (CL)同态加密方案）
}puzzle_st;   // Random Puzzle方案中的puzzle

typedef puzzle_st *puzzle_t;

#define puzzle_null(puzzle) puzzle=NULL;

#define puzzle_new(puzzle)                                 \
  do {                                                    \
    printf("\n Size of g_to_the_alpha : %d B\n",sizeof(ec_t));\
    puzzle = malloc(sizeof(puzzle_st));                    \
    if (puzzle == NULL) {                                  \
      RLC_THROW(ERR_NO_MEMORY);                           \
    }                                                     \
    ec_new((puzzle)->g_to_the_alpha);                      \
    cl_ciphertext_new((puzzle)->ctx_alpha);                \
  } while (0)

#define puzzle_free(puzzle)                                \
  do {                                                    \
    ec_free((puzzle)->g_to_the_alpha);                     \
    cl_ciphertext_free((puzzle)->ctx_alpha);               \
    free(puzzle);                                          \
    puzzle = NULL;                                         \
  } while (0)



int RP_setUP(RP_t rp_params);   // Random Puzzle系统的初始化算法
int RP_gen(puzzle_t puzzle,const RP_t rp_params);   // Random Puzzle系统的Puzzle生成算法
int RP_solve(const RP_t rp_params,const puzzle_t puzzle);   // Random Puzzle系统的Puzzle解密算法
int RP_rand(puzzle_t puzzle_rand,const RP_pp_t rp_pp,const puzzle_t puzzle);    // Random Puzzle系统的Puzzle随机化算法

#endif // A2L_SCHNORR_INCLUDE_TUMBLER