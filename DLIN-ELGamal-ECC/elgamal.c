#include <gmp.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <fcntl.h>
#include <math.h>
#include <unistd.h>
#include <string.h>
#include <stdio_ext.h>

typedef struct point {
  mpz_t x, y;
} point;    // ecc上的点类型定义


typedef struct elliptic_curve {
  mpz_t a, b, p,q;
  point *base;
} elliptic_curve;   // ecc曲线定义，a，b为ecc曲线方程中的系数，p为该方程的模数，q为ecc曲线中选定的基点的阶，base为ecc曲线中的基点

typedef struct elgam_ctx {
  mpz_t dom_par_q, dom_par_p, dom_par_g;
  mpz_t priv_x, pub_h, eph_k;
} elgam_ctx;        // 素数域中基于DDH假设的elgamal加密系统的参数（经典elgamal加密方案）

typedef struct ciphertext {
  mpz_t c1, c2;
} ciphertext;       // 素数域中基于DDH假设的elgamal加密系统的密文结构（经典elgamal加密方案）

typedef struct pub_key{
	point *u,*v,*h;
}pub_key;           // ecc中基于DLIN假设的elgamal加密系统的公钥结构（线性elgama加密方案——LE）

typedef struct cipherec {
	point *c1, *c2,*c3;
} cipherec;         // ecc中基于DLIN假设的elgamal加密系统的密文结构（线性elgama加密方案——LE）

typedef struct elgam_ec_ctx {
	pub_key *pk;
	point *sk,*eph_k;
	elliptic_curve *ec;
} elgam_ec_ctx;     // ecc中基于DLIN假设的elgamal加密系统的参数（线性elgama加密方案——LE）

void init_point(point **);  // 用于为ecc曲线上的点开辟存储空间
void destroy_point(point *);    // 用于回收点的存储空间

point* ecc_scalar_mul(elliptic_curve *, mpz_t, point *);    // 用于完成ecc曲线上定义的点的数乘操作，即nP（P为曲线上的点）
point* ecc_addition(elliptic_curve *, point *, point *);    // 用于完成ecc曲线上定义的点的加法操作，即P+Q（P、Q为曲线上的点)
point* ecc_doubling(elliptic_curve *, point *);             // 用于完成ecc曲线上点的倍乘操作，即2P（P为曲线上的点）

void init_point(point **p) 
{
	*p = (point*) malloc(sizeof(point));
	mpz_init((*p)->x); //set value to 0
	mpz_init((*p)->y);
}


void destroy_point(point *p)
{
	if (p) {
		mpz_clears(p->x, p->y, NULL);
		free(p);
		p = NULL;
	}
}

point* ecc_scalar_mul(elliptic_curve *ec, mpz_t m, point *p) {
	if (mpz_cmp_ui(m, 1) == 0) { // if equal retrun the number itself.
		return p;
	} else if (mpz_even_p(m) == 0) { // return true/1 if even
		mpz_sub_ui(m, m, 1); // m = m-1
		return ecc_addition(ec, p, ecc_scalar_mul(ec,m,p));
	} else {
		mpz_div_ui(m, m, 2); // m = m/2
		return ecc_scalar_mul(ec, m, ecc_doubling(ec, p));
	}
}

point* ecc_doubling(elliptic_curve *ec, point *p)
{
	// https://crypto.stackexchange.com/questions/64456/problem-on-elliptic-curve-point-doubling
	point *r = malloc(sizeof(point));
	mpz_init(r->x);
	mpz_init(r->y);
	mpz_mod(p->x, p->x, ec->p);
	mpz_mod(p->y, p->y, ec->p);
	mpz_t temp, slope;
	mpz_init(temp);
	mpz_init_set_ui(slope, 0);

	// temp = 2*y1
	mpz_mul_ui(temp, p->y, 2);
	// temp = temp^-1 mod p
	mpz_invert(temp, temp, ec->p);
	// slope = x1*x1 = x1^2
	mpz_mul(slope, p->x, p->x);
	// slope = slope * 3
	mpz_mul_ui(slope, slope, 3);

	// slope = slope + a
	mpz_add(slope, slope, ec->a);

	// slope = slope * temp (numinator * denuminator)
	mpz_mul(slope, slope, temp);
	// slope = slope mod p
	mpz_mod(slope, slope, ec->p);

	// x3 = slope * slope
	mpz_mul(r->x, slope, slope);
	mpz_sub(r->x, r->x, p->x);
	mpz_sub(r->x, r->x, p->x);
	mpz_mod(r->x, r->x, ec->p);
	mpz_sub(temp, p->x, r->x);
	mpz_mul(r->y, slope, temp);
	mpz_sub(r->y, r->y, p->y);
	mpz_mod(r->y, r->y, ec->p);

	//return r;
	mpz_clears(temp, slope, NULL);
	return r;
}

point* ecc_addition(elliptic_curve *ec, point *p, point *q) // ec->p is prime
{
	point *r = malloc(sizeof(point));
	mpz_init(r->x);
	mpz_init(r->y);
	mpz_mod(p->x, p->x, ec->p); //1st = 2nd % 3rd
	mpz_mod(p->y, p->y, ec->p);
	mpz_mod(q->x, q->x, ec->p);
	mpz_mod(q->y, q->y, ec->p);
	mpz_t temp,slope;
	mpz_init(temp);
	mpz_init_set_ui(slope, 0);

	//if (mpz_cmp(p->x, q->x) == 0 && mpz_cmp(p->y, q->y) == 0)
	//  return ecc_doubling(ec, p);

	// temp = x1-x2
	mpz_sub(temp, p->x, q->x);
	// temp = temp mod p
	mpz_mod(temp, temp, ec->p);
	// temp^-1 mod p
	mpz_invert(temp, temp, ec->p);
	// slope = y1-y2
	mpz_sub(slope, p->y, q->y);
	// slope = slope * temp
	mpz_mul(slope, slope, temp);
	// slope = slope mod p
	mpz_mod(slope, slope, ec->p);

	// x3 = slope * slope = alpha^2
	mpz_mul(r->x, slope, slope);

	// x3 = x3 - x1
	mpz_sub(r->x, r->x, p->x);
	// x3 = x3 - x2
	mpz_sub(r->x, r->x, q->x);
	// x3 = x3 mod p
	mpz_mod(r->x, r->x, ec->p);

	// temp = x1 - x3
	mpz_sub(temp, p->x, r->x);
	// y3 = slope * temp
	mpz_mul(r->y, slope, temp);
	// y3 = y3 - y1
	mpz_sub(r->y, r->y, p->y);
	// y3 = y3 mod p
	mpz_mod(r->y, r->y, ec->p);
	//return r;
	mpz_clears(temp, slope, NULL);
	return r;
}

/*
  Sets r to a random GMP integer with the specified number
  of bits.
*/
void get_random_n_bits(mpz_t r, size_t bits)
{
	size_t size = (size_t) ceilf(bits/8);
	char *buffer = (char*) malloc(sizeof(char)*size);
	int prg = open("/dev/random", O_RDONLY);
	read(prg, buffer, size);
	close(prg);
	mpz_import (r, size, 1, sizeof(char), 0, 0, buffer);
	free(buffer);
}


/*
  Sets r to a random GMP *prime* integer, smaller than max.
*/
void get_random_n_prime(mpz_t r, mpz_t max) 
{
	do {
		get_random_n_bits(r, mpz_sizeinbase(max, 2));
		mpz_nextprime(r, r);
	} while (mpz_cmp(r, max) >= 0);
}


/*
  Sets r to a random GMP integer smaller than max.
*/
void get_random_n(mpz_t r, mpz_t max) 
{
	do {
		get_random_n_bits(r, mpz_sizeinbase(max, 2));
	} while (mpz_cmp(r, max) >= 0);
}


// 素数域上的经典elgamal加密方案
/*
 Init structure. Set domain parameters p, q and g
 */
void init_elgam(elgam_ctx **ectx, size_t bits) 
{
	*ectx = (elgam_ctx*) malloc(sizeof(elgam_ctx));
	// 1. find large prime p for domain parameter
	mpz_t p, g, x, h;
	mpz_init((*ectx)->dom_par_p);
	mpz_init((*ectx)->dom_par_g);
	mpz_init((*ectx)->priv_x);
	mpz_init((*ectx)->pub_h);
	mpz_init((*ectx)->eph_k);
	get_random_n_bits((*ectx)->dom_par_p, bits);
	mpz_nextprime((*ectx)->dom_par_p, (*ectx)->dom_par_p);
	gmp_printf("\n\np = %Zd\n", (*ectx)->dom_par_p);

	get_random_n_prime((*ectx)->dom_par_g, (*ectx)->dom_par_p);
	gmp_printf("g = %Zd\n", (*ectx)->dom_par_g);

	get_random_n((*ectx)->priv_x, (*ectx)->dom_par_p);
	gmp_printf("x = %Zd\n", (*ectx)->priv_x);
	/* h = g^x (mod n) */
	mpz_powm_sec((*ectx)->pub_h, (*ectx)->dom_par_g, (*ectx)->priv_x, (*ectx)->dom_par_p);
	gmp_printf("h = %Zd\n\n", (*ectx)->pub_h);
}


void destroy_elgam(elgam_ctx *ectx) 
{
	if (ectx) {
		mpz_clears(ectx->dom_par_p, ectx->dom_par_g, ectx->dom_par_q, NULL);
		mpz_clears(ectx->priv_x, ectx->pub_h, ectx->eph_k, NULL);
		free(ectx);
		ectx = NULL;
	}
}


void destroy_ciphertxt(ciphertext *ct) 
{
	if (ct) {
		mpz_clears(ct->c1, ct->c2, NULL);
		free(ct);
		ct = NULL;
	}
}

ciphertext* encrypt(mpz_t m, elgam_ctx *ectx)
{
	ectx->eph_k;
	get_random_n(ectx->eph_k, ectx->dom_par_p);
	ciphertext *ct = malloc(sizeof(ciphertext));
	mpz_init(ct->c1);
	mpz_init(ct->c2);
	mpz_powm_sec(ct->c1, ectx->dom_par_g, ectx->eph_k, ectx->dom_par_p);
	mpz_powm_sec(ct->c2, ectx->pub_h, ectx->eph_k, ectx->dom_par_p);
	mpz_mul(ct->c2, m, ct->c2);
	mpz_mod(ct->c2, ct->c2, ectx->dom_par_p);
	gmp_printf("c1 = %Zd\n", ct->c1);
	gmp_printf("c2 = %Zd\n\n", ct->c2);
	return ct;
}


void decrypt(mpz_t msg, ciphertext *ct, elgam_ctx *ectx) 
{
	mpz_powm_sec(ct->c1, ct->c1, ectx->priv_x, ectx->dom_par_p);
	mpz_invert(ct->c1, ct->c1, ectx->dom_par_p);
	mpz_mul(msg, ct->c2, ct->c1);
	mpz_mod(msg, msg, ectx->dom_par_p);
}

// ecc域上基于DLIN假设的elgamal加密方案（LE）

/* setup elliptic curve, public and private key
 Using the brainpoolP160r1 - EC domain parameters
 http://www.ecc-brainpool.org/download/Domain-parameters.pdf
 */
void init_elgam_ec(elgam_ec_ctx **eec_ctx)
{
	mpz_t a,b,zero;     // a,b用于以下等式：u=aG，v=bG，G为ecc曲线上的基点；zero为mpz类型的数值0
    mpz_init(a);
    mpz_init(b);
    mpz_init(zero);
	mpz_set_str(zero, "0", 16); 
    *eec_ctx = (elgam_ec_ctx*) malloc(sizeof(elgam_ec_ctx));
    elliptic_curve *ecc = malloc(sizeof(elliptic_curve));
    (*eec_ctx)->ec = ecc;

	//Set elliptic curve.
    mpz_set_str(ecc->a, "340E7BE2A280EB74E2BE61BADA745D97E8F7C300", 16); 
    mpz_set_str(ecc->b, "1E589A8595423412134FAA2DBDEC95C8D8675E58", 16); 
    mpz_set_str(ecc->p, "E95E4A5F737059DC60DFC7AD95B3D8139515620F", 16); 
    mpz_set_str(ecc->q, "E95E4A5F737059DC60DF5991D45029409E60FC09", 16); 


	// Set the base point.
	init_point(&(ecc->base));
	mpz_set_str(ecc->base->x, "BED5AF16EA3F6A4F62938C4631EB5AF7BDBCDBC3", 16); 
	mpz_set_str(ecc->base->y, "1667CB477A1A8EC338F94741669C976316DA6321", 16); 
	gmp_printf("\np = %Zd\n", ecc->p);

	// Choose a random private key from Zp —— sk=（x,y），x=b，与u配对；y=a，与v配对
	init_point(&((*eec_ctx)->sk));

    // 保证获得随机数x、y不为0/kq
	get_random_n((*eec_ctx)->sk->x, ecc->p);
	while(!mpz_cmp((*eec_ctx)->sk->x,ecc->q) || !mpz_cmp((*eec_ctx)->sk->x,zero))
	{
		get_random_n((*eec_ctx)->sk->x, ecc->p);		
	}
	gmp_printf("x = %Zd\n", (*eec_ctx)->sk->x);
	get_random_n((*eec_ctx)->sk->y, ecc->p);
	while(!mpz_cmp((*eec_ctx)->sk->y,ecc->q) || !mpz_cmp((*eec_ctx)->sk->y,zero))
	{
		get_random_n((*eec_ctx)->sk->y, ecc->p);		
	}
	gmp_printf("y = %Zd\n", (*eec_ctx)->sk->y);
	mpz_set(a,(*eec_ctx)->sk->y);
	gmp_printf("a = %Zd\n", a);
	mpz_set(b,(*eec_ctx)->sk->x);
	gmp_printf("b = %Zd\n", b);

	// generate pub key(u,v,h)，h=xu=yv=abG
	mpz_t tmp;
    point *result;
    pub_key *pk = malloc(sizeof(pub_key));
    (*eec_ctx)->pk = pk;
	init_point(&((*eec_ctx)->pk->u));
	init_point(&((*eec_ctx)->pk->v));
	init_point(&(result));
	init_point(&((*eec_ctx)->pk->h));
    // 计算u=aG
	mpz_init_set(tmp, a); 
	(*eec_ctx)->pk->u = ecc_scalar_mul((*eec_ctx)->ec, tmp, ecc->base);  
	gmp_printf("u =  (%Zd,%Zd)\n\n", (*eec_ctx)->pk->u->x, (*eec_ctx)->pk->u->y);
	mpz_clears(tmp, NULL);
    // 计算v=bG   
	mpz_init_set(tmp, b); 
	(*eec_ctx)->pk->v = ecc_scalar_mul((*eec_ctx)->ec, tmp, ecc->base);  
	gmp_printf("v =  (%Zd,%Zd)\n\n", (*eec_ctx)->pk->v->x, (*eec_ctx)->pk->v->y);
	mpz_clears(tmp, NULL);
    // 计算xu
	mpz_init_set(tmp, (*eec_ctx)->sk->x); 
	result = ecc_scalar_mul((*eec_ctx)->ec, tmp, (*eec_ctx)->pk->u);  
	gmp_printf("Result xu=  (%Zd,%Zd)\n\n", result->x, result->y);
    destroy_point(result);
	mpz_clears(tmp, NULL);
    // 计算yv
	mpz_init_set(tmp, (*eec_ctx)->sk->y); 
	init_point(&(result));
	result = ecc_scalar_mul((*eec_ctx)->ec, tmp, (*eec_ctx)->pk->v);  
	gmp_printf("Result yv=  (%Zd,%Zd)\n\n", result->x, result->y);
	mpz_clears(tmp, NULL);
    // h=xu=yv
	mpz_set((*eec_ctx)->pk->h->x,result->x);
	mpz_set((*eec_ctx)->pk->h->y,result->y);
	gmp_printf("Result h=  (%Zd,%Zd)\n\n", (*eec_ctx)->pk->h->x, (*eec_ctx)->pk->h->y);
    destroy_point(result);

	mpz_clears(a, NULL);
	mpz_clears(b, NULL);
	mpz_clears(zero, NULL);
}


// void test_init_elgam_ec(elgam_ec_ctx **eec_ctx)
// {
//     *eec_ctx = (elgam_ec_ctx*) malloc(sizeof(elgam_ec_ctx));
//     elliptic_curve *ecc = malloc(sizeof(elliptic_curve));
//     (*eec_ctx)->ec = ecc;

// 	mpz_init_set_ui(ecc->a, 1);
// 	mpz_init_set_ui(ecc->b, 3);
// 	mpz_init_set_ui(ecc->p, 23);

// 	mpz_init((*eec_ctx)->priv_key);
// 	init_point(&(ecc->base));
// 	init_point(&((*eec_ctx)->pub_key));

// 	//mpz_init_set_ui(ecc->base->x, 21);
// 	//mpz_init_set_ui(ecc->base->y, 1);
// }

// 释放ecc域上的基于DLIN假设的elgamal加密方案的系统参数的内存空间
void destroy_elgam_ec(elgam_ec_ctx *eec_ctx) 
{
	if (eec_ctx) {	 
		mpz_clears(eec_ctx->ec->a, eec_ctx->ec->b, eec_ctx->ec->p, eec_ctx->ec->q,NULL);
		destroy_point(eec_ctx->ec->base);
		destroy_point(eec_ctx->sk);
		destroy_point(eec_ctx->pk->u);
		destroy_point(eec_ctx->pk->v);
		destroy_point(eec_ctx->pk->h);
		if (eec_ctx->ec) {
			free(eec_ctx->ec);
			eec_ctx->ec = NULL;
		}
		if (eec_ctx->pk) {
			free(eec_ctx->pk);
			eec_ctx->pk = NULL;
		}
		free(eec_ctx);
		eec_ctx = NULL;
	}
}

// 释放ecc域上的基于DLIN假设的elgamal加密方案的密文的内存空间
void destroy_cipherec(cipherec *c)
{
	if (c) {
		destroy_point(c->c1);
		destroy_point(c->c2);
		destroy_point(c->c3);
		free(c);
		c = NULL;
	}
}

//ecc域上的基于DLIN假设的elgamal加密方案的加密算法
void encrypt_ec(elgam_ec_ctx *eec, point *pm)       // pm为明文在ecc曲线上的映射点
{
	// gmp_printf("Encrypted: (%Zd,%Zd)\n", pm->x, pm->y);  

	init_point(&eec->eph_k);

    // 选取加密过程中所需的随机数r1，r2（from Zp）
	get_random_n(eec->eph_k->x, eec->ec->p); //eph_k->x is random r1.
	get_random_n(eec->eph_k->y, eec->ec->p); //eph_k->y is random r2.
	// gmp_printf("\nEphemeral key r1 = %Zd\n", eec->eph_k->x);
	// gmp_printf("\nEphemeral key r2 = %Zd\n", eec->eph_k->y);

	cipherec *cipher = malloc(sizeof(cipherec));
	init_point(&cipher->c1);
	init_point(&cipher->c2);
	init_point(&cipher->c3);
	mpz_t tmp;

    // 计算r1*u
	mpz_init_set(tmp, eec->eph_k->x); //tmp is set to r1
	cipher->c1 = ecc_scalar_mul(eec->ec, tmp, eec->pk->u); 
	mpz_clears(tmp, NULL);

    // 计算r2*v
	mpz_init_set(tmp, eec->eph_k->y); //tmp is set to r2
	cipher->c2 = ecc_scalar_mul(eec->ec, tmp, eec->pk->v); 
	mpz_clears(tmp, NULL);

	mpz_t r1_add_r2;
	mpz_add(r1_add_r2,eec->eph_k->x,eec->eph_k->y);     // 计算r1+r2

    // 计算（r1+r2）*h
	mpz_init_set(tmp, r1_add_r2);
	cipher->c3 = ecc_scalar_mul(eec->ec, tmp, eec->pk->h);
	mpz_clears(tmp, NULL);

    // 计算（r1+r2）*h+pm
	gmp_printf("Cipher C1: (%Zd,%Zd)\n", cipher->c1->x, cipher->c1->y);
	gmp_printf("Cipher C2: (%Zd,%Zd)\n", cipher->c2->x, cipher->c2->y);
	cipher->c3 = ecc_addition(eec->ec, cipher->c3, pm);
	gmp_printf("Cipher C3 with msg: (%Zd,%Zd)\n", cipher->c3->x, cipher->c3->y);
	destroy_cipherec(cipher);
	destroy_point(eec->eph_k);
}


void decrypt_ec(elgam_ec_ctx *eec, point *c1, point *c2,point *c3)
{
	point *d1, *d2,*res;
	init_point(&d1);
	init_point(&d2);
	init_point(&res);
	mpz_t tmp;

    // 计算d1=x*c1
	mpz_init_set(tmp, eec->sk->x);
	d1 = ecc_scalar_mul(eec->ec, tmp, c1); 
	mpz_clears(tmp, NULL);
	// gmp_printf("D1=(%Zd,%Zd)\n", d1->x, d1->y);

    // 计算d2=y*c2
	mpz_init_set(tmp, eec->sk->y);
	d2 = ecc_scalar_mul(eec->ec, tmp, c2); 
	mpz_clears(tmp, NULL);
	// gmp_printf("D2=(%Zd,%Zd)\n", d2->x, d2->y);

    // 计算res=-(d1+d2)
	res = ecc_addition(eec->ec, d1, d2); 	
	mpz_neg(res->y, res->y); // x = -x

	res = ecc_addition(eec->ec, c3, res);   // 计算res=res+c3=pm,得到明文pm
	// gmp_printf("Decrypted: (%Zd,%Zd)\n", res->x, res->y);
	destroy_point(d1);
	destroy_point(d2);
	destroy_point(res);
}


int main()
{
	clock_t start,stop;     // 用于测算程序运行时间
	double run_time;        // 存储算法的实际运行时间，单位(s)
	// ElGamal-EC
	elgam_ec_ctx *eec;
	init_elgam_ec(&eec);
	char input[100] = {0};

	point *p, *c1, *c2,*c3;
	point *d;
	init_point(&p);
	init_point(&c1);
	init_point(&c2);
	init_point(&c3);

	while (1) {
		__fpurge(stdin);
		printf("\nEnter 1 to encrypt and 0 to decrypt:");
		memset(input, 0, 100);
		fgets(input, 100, stdin);
		input[strlen(input)-1] = '\0';
		int is_encrypt = atoi(input);

		/* atoi() will return 0 for special characters also hence strncmp is used.*/
		if(!( (is_encrypt == 1) ^ ((is_encrypt == 0) && !strncmp(input, "0", 1))))
		{
			printf("\n Invalid encrypt/decrypt value. Enter 1 to encrypt 0 to decrypt.\n");
			continue;
		}

		if (is_encrypt == 1) {
			// Elgamal encryption.
			// c1 = r1*u (rand r1 * point u)
			// c2 = r2*v (rand r2 * point v)
            // c3= （r1+r2）*h + Pm (rand （r2+r1） * point h) + point on curve (secret message)
			gmp_printf("\nEnter Plain text in the form of point P(x,y) Usage:x,y\n");
			gmp_scanf("%Zd,%Zd", p->x,p->y);
			printf("\nEncrypting!!!!!!!!!!!!!!!!!\n");

            // 计算加密过程的时间
			start=clock();
			encrypt_ec(eec, p);
			stop=clock();
			run_time=(double)(stop-start)/CLOCKS_PER_SEC;
			printf("\nthe time of encrypt :%f\n",run_time);
		}

		if (is_encrypt == 0) {
			// Elgamal Decryption.
			// c1 * x = c1' = r1*u*x = r1*a*G*x = r1*a*G*b = r1*a*b*G = r1*h
			// c2 * y = c2' = r2*v*y = r2*b*G*x = r2*b*G*a = r2*a*b*G = r2*h
			// Pm = c3 - (c1+c2) = Pm + (r1+r2)*h - (r1+r2)*h
			gmp_printf("\nEnter cipher text C1, C2,C3 in the form of point P(x,y)\n");
			gmp_printf("\nEnter C1. Usage:x,y\n");
			gmp_scanf("%Zd,%Zd", c1->x,c1->y);
			gmp_printf("\nEnter C2. Usage:x,y\n");
			gmp_scanf("%Zd,%Zd", c2->x,c2->y);
			gmp_printf("\nEnter C3. Usage:x,y\n");
			gmp_scanf("%Zd,%Zd", c3->x,c3->y);
			printf("\nDecrypting!!!!!!!!!!!!!!!!!\n");
        
            // 计算解密过程的时间
			start=clock();
			decrypt_ec(eec, c1, c2,c3);
			stop=clock();
			run_time=(double)(stop-start)/CLOCKS_PER_SEC;
			printf("\nthe time of decrypt :%f\n",run_time);
		}
	}
	destroy_elgam_ec(eec);
	return 0;
}