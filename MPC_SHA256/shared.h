 /*
 ============================================================================
 Name        : shared.h
 Author      : Sobuno
 Version     : 0.1
 Description : Common functions for the prover and verifier
 ============================================================================
 */

#ifndef SHARED_H_
#define SHARED_H_
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <openssl/applink.c>
#endif
#include <openssl/rand.h>
#include "omp.h"
#include "time_utils.h"

#define VERBOSE FALSE

const int NUM_ROUNDS = 136;


uint32_t rand32() {
	uint32_t x;
	x = rand() & 0xff;
	x |= (rand() & 0xff) << 8;
	x |= (rand() & 0xff) << 16;
	x |= (rand() & 0xff) << 24;

	return x;
}

void printbits(uint32_t n) {
	if (n) {
		printbits(n >> 1);
		printf("%d", n & 1);
	}
}

typedef struct {
	unsigned char x[64];
	uint32_t y[ySize];
} View;

typedef struct {
	uint32_t yp[3][8];
	unsigned char h[3][32];
} a;

typedef struct {
	unsigned char ke[16];
	unsigned char ke1[16];
	View ve;
	View ve1;
	unsigned char re[4];
	unsigned char re1[4];
} z;

#define RIGHTROTATE(x,n) (((x) >> (n)) | ((x) << (32-(n))))
#define LEFTROTATE(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b)   x= (b)&1 ? (x)|(1 << (i)) : (x)&(~(1 << (i)))


void handleErrors(void)
{
	ERR_print_errors_fp(stderr);
	abort();
}


EVP_CIPHER_CTX setupAES(const unsigned char key[16]) {
	EVP_CIPHER_CTX ctx;
	EVP_CIPHER_CTX_init(&ctx);

	///* A 128 bit key */
	//unsigned char *key = (unsigned char *)"01234567890123456";

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"01234567890123456";

	/* Create and initialise the context */
	//if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if(1 != EVP_EncryptInit_ex(&ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();
	return ctx;
}

// required size for randomness[]
void getAllRandomness(
		const unsigned char key[16] /*IN*/,
		unsigned char *randomness /*OUT*/,
		int randomnessBits) {
	//"SHA-256"
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

	//"SHA-1"
	//Generate randomness: We use 365*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 365*32/128 = 91.25 iterations. Let's just round up.

	EVP_CIPHER_CTX ctx;
	ctx = setupAES(key);
	unsigned char *plaintext =
			(unsigned char *)"0000000000000000";
	int len;
	for(int j=0; j<randomnessBits/128; j++) {
		if(1 != EVP_EncryptUpdate(&ctx, &(randomness[j*16]), &len,
					plaintext, strlen ((char *)plaintext)))
			handleErrors();

	}
	EVP_CIPHER_CTX_cleanup(&ctx);
}


//OK
// "SHA-1" --> randomness[1472]
//uint32_t getRandom32(unsigned char randomness[2912], int randCount) {
uint32_t getRandom32(const unsigned char* randomness, int randCount) {
	uint32_t ret;
//	printf("Randomness at %d: %02X %02X %02X %02X\n", randCount,
//		randomness[randCount], randomness[randCount+1], randomness[randCount+2], randomness[randCount+3]);
	memcpy(&ret, &(randomness[randCount]), 4);
	return ret;
}


void init_EVP() {
	/* Initialise the library */
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);
}

void cleanup_EVP() {
	/* Clean up */
	EVP_cleanup();
	ERR_free_strings();
}

//FIXME ref to View?
void H(unsigned char hash[SHA256_DIGEST_LENGTH], const unsigned char k[16], const View v, const unsigned char r[4]) {
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, k, 16);
	SHA256_Update(&ctx, &v, sizeof(v));
	SHA256_Update(&ctx, r, 4);
	SHA256_Final(hash, &ctx);
}

// ROM: H(y=f(x), commitments)
void H3(int* es /*OUT*/,
		const uint32_t y[8] /*IN*/ /* final hash*/,
		const a* as /*IN of size s*/,
		const int s /*IN size*/) {

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, y, 32); //FIXME 20 (SHA1/shared.h)or 32(SHA256/shared.h) ???
	SHA256_Update(&ctx, as, sizeof(a)*s);
	SHA256_Final(hash, &ctx);

	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < s) {
		if(bitTracker >= SHA256_DIGEST_LENGTH*8) {
			//Generate new hash as we have run out of bits in the previous hash
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, sizeof(hash));
			SHA256_Final(hash, &ctx);
			bitTracker = 0;
		}

		int b1 = GETBIT(hash[bitTracker/8], bitTracker % 8);
		int b2 = GETBIT(hash[(bitTracker+1)/8], (bitTracker+1) % 8);
		if(b1 == 0) {
			if(b2 == 0) {
				es[i] = 0;
				bitTracker += 2;
				i++;
			} else {
				es[i] = 1;
				bitTracker += 2;
				i++;
			}
		} else {
			if(b2 == 0) {
				es[i] = 2;
				bitTracker += 2;
				i++;
			} else {
				bitTracker += 2;
			}
		}
	}

	/*srand(*hash);
	for(int i=0; i<s; i++) {
		es[i] = random_at_most(2);
	}*/
}

//FIXME View?
// copies the last *words* bits of v.y
void output(uint32_t* result, View v, int words /*5 for SHA-1 or 8 for SHA-256*/) {
	memcpy(result, &v.y[ySize - words], words * 4);
}

void reconstruct(
		const uint32_t* y0, const uint32_t* y1, const uint32_t* y2,
		uint32_t* result) {
	//printf("reconstruct for %X %X %X\n", *y0, *y1, *y2);
	for (int i = 0; i < 8; i++) {
		result[i] = y0[i] ^ y1[i] ^ y2[i];
	}
}

omp_lock_t *locks;

// Locking callback
void openmp_locking_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK)
  {
    omp_set_lock(&locks[type]);
  }
  else
  {
    omp_unset_lock(&locks[type]);
  }
}

// Thread ID callback
unsigned long openmp_thread_id(void)
{
  return (unsigned long)omp_get_thread_num();
}

void openmp_thread_setup(void)
{
  int i;

  locks = OPENSSL_malloc(CRYPTO_num_locks() * sizeof(omp_lock_t));
  for (i=0; i<CRYPTO_num_locks(); i++)
  {
    omp_init_lock(&locks[i]);
  }

  CRYPTO_set_id_callback((unsigned long (*)())openmp_thread_id);
  CRYPTO_set_locking_callback((void (*)())openmp_locking_callback);
}

void openmp_thread_cleanup(void)
{
  int i;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    omp_destroy_lock(&locks[i]);
  OPENSSL_free(locks);
}





//OK
void mpc_XOR(const uint32_t x[3], const uint32_t y[3], uint32_t z[3]) {
	for(int party=0; party<3; party++)
		z[party] = x[party] ^ y[party];
}

//OK
void mpc_XOR_verify(const uint32_t x[2], const uint32_t y[2], uint32_t z[2]) {
	z[0] = x[0] ^ y[0];
	z[1] = x[1] ^ y[1];
}

//OK
void mpc_RIGHTROTATE(const uint32_t x[], int i, uint32_t z[]) {
	for(int party=0; party<3; party++)
		z[party] = RIGHTROTATE(x[party], i);
}

//OK
void mpc_RIGHTROTATE_verify(const uint32_t x[], int i, uint32_t z[]) {
	z[0] = RIGHTROTATE(x[0], i);
	z[1] = RIGHTROTATE(x[1], i);
}

//OK
void mpc_LEFTROTATE(const uint32_t x[], int i, uint32_t z[]) {
	for(int party=0; party<3; party++)
		z[party] = LEFTROTATE(x[party], i);
}

void mpc_LEFTROTATE_verify(const uint32_t x[], int i, uint32_t z[]) {
	z[0] = LEFTROTATE(x[0], i);
	z[1] = LEFTROTATE(x[1], i);
}

//OK
void mpc_RIGHTSHIFT(const uint32_t x[3], int i, uint32_t z[3]) {
	for(int party=0; party<3; party++)
		z[party] = x[party] >> i;
}

//OK
void mpc_RIGHTSHIFT_verify(const uint32_t x[2], int i, uint32_t z[2]) {
	z[0] = x[0] >> i;
	z[1] = x[1] >> i;
}

//OK
void mpc_NEGATE(const uint32_t x[3], uint32_t z[3]) {
	for(int party=0; party<3; party++)
		z[party] = ~x[party];
}

//OK
void mpc_NEGATE_verify(const uint32_t x[2], uint32_t z[2]) {
	z[0] = ~x[0];
	z[1] = ~x[1];
}

//FIXME Views? ptr
void mpc_ADD(
		const uint32_t x[3] /*IN*/,
		const uint32_t y[3] /*IN*/,
		uint32_t z[3] /*OUT*/,
		const unsigned char *randomness[3] /*IN*/,
		int* randCount /*OUT*/,
		View views[3] /*OUT*/,
		int* countY /*OUT*/) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount),
			getRandom32(randomness[1], *randCount),
			getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];
	uint8_t t;

	for(int i=0;i<31;i++)
	{
		for(int j=0; j<3; j++){
			a[j]=GETBIT(x[j]^c[j],i);
			b[j]=GETBIT(y[j]^c[j],i);
		}

		// FIXME unroll loops
		for(int j=0; j<3; j++){
			t = (a[j]&b[(j+1) % 3]) ^ (a[(j+1)%3]&b[j]) ^ GETBIT(r[(j+1)%3],i);
			SETBIT(c[j],i+1, t ^ (a[j]&b[j]) ^ GETBIT(c[j],i) ^ GETBIT(r[j],i));
		}

//		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
//		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));
//
//		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
//		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));
//
//		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
//		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));
	}

	for(int j=0; j<3; j++){
		z[j]=x[j]^y[j]^c[j];
	}

	for(int j=0; j<3; j++){
		views[j].y[*countY] = c[j];
	}
	*countY += 1;

	/*views[0].y[countY] = z[0];
	views[1].y[countY] = z[1];
	views[2].y[countY] = z[2];
	countY++;*/
}

//Previously: unsigned char randomness[2][2912], int* randCount, int* countY) {
int mpc_ADD_verify(
		const uint32_t x[2],
		const uint32_t y[2],
		uint32_t z[2],
		const View ve,
		const View ve1,
		const unsigned char *randomness[2],
		int* randCount,
		int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint8_t a[2], b[2];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^ve.y[*countY],i);
		a[1]=GETBIT(x[1]^ve1.y[*countY],i);

		b[0]=GETBIT(y[0]^ve.y[*countY],i);
		b[1]=GETBIT(y[1]^ve1.y[*countY],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		if(GETBIT(ve.y[*countY],i+1) != (t ^ (a[0]&b[0]) ^ GETBIT(ve.y[*countY],i) ^ GETBIT(r[0],i))) {
			return 1;
		}
	}

	z[0]=x[0]^y[0]^ve.y[*countY];
	z[1]=x[1]^y[1]^ve1.y[*countY];
	(*countY)++;
	return 0;
}


void mpc_ADDK(
		const uint32_t x[3],
		const uint32_t y,
		uint32_t z[3],
		const unsigned char *randomness[3],
		int* randCount,
		View views[3] /* OUT */,
		int* countY) {
	uint32_t c[3] = { 0 };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount),
			getRandom32(randomness[1], *randCount),
			getRandom32(randomness[2], *randCount)};
	*randCount += 4;

	uint8_t a[3], b[3];

	uint8_t t;

	for(int i=0;i<31;i++)
	{
		a[0]=GETBIT(x[0]^c[0],i);
		a[1]=GETBIT(x[1]^c[1],i);
		a[2]=GETBIT(x[2]^c[2],i);

		b[0]=GETBIT(y^c[0],i);
		b[1]=GETBIT(y^c[1],i);
		b[2]=GETBIT(y^c[2],i);

		t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
		SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i));

		t = (a[1]&b[2]) ^ (a[2]&b[1]) ^ GETBIT(r[2],i);
		SETBIT(c[1],i+1, t ^ (a[1]&b[1]) ^ GETBIT(c[1],i) ^ GETBIT(r[1],i));

		t = (a[2]&b[0]) ^ (a[0]&b[2]) ^ GETBIT(r[0],i);
		SETBIT(c[2],i+1, t ^ (a[2]&b[2]) ^ GETBIT(c[2],i) ^ GETBIT(r[2],i));
	}

	z[0]=x[0]^y^c[0];
	z[1]=x[1]^y^c[1];
	z[2]=x[2]^y^c[2];

	views[0].y[*countY] = c[0];
	views[1].y[*countY] = c[1];
	views[2].y[*countY] = c[2];
	*countY += 1;
}

//OK
void mpc_AND(
		const uint32_t x[3],
		const uint32_t y[3],
		uint32_t z[3] /*OUT*/,
		const unsigned char *randomness[3],
		int* randCount,
		View views[3] /*OUT*/,
		int* countY) {
	//uint32_t r[3] = { newRandom(&ctx[0]), newRandom(&ctx[1]),newRandom(&ctx[2]) };
	uint32_t r[3] = { getRandom32(randomness[0], *randCount),
			getRandom32(randomness[1], *randCount),
			getRandom32(randomness[2], *randCount)};
	*randCount += 4;
	//kCount++;
	uint32_t t[3];// = { 0 };

	t[0] = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	t[1] = (x[1] & y[2]) ^ (x[2] & y[1]) ^ (x[1] & y[1]) ^ r[1] ^ r[2];
	t[2] = (x[2] & y[0]) ^ (x[0] & y[2]) ^ (x[2] & y[2]) ^ r[2] ^ r[0];
	z[0] = t[0];
	z[1] = t[1];
	z[2] = t[2];
	views[0].y[*countY] = z[0];
	views[1].y[*countY] = z[1];
	views[2].y[*countY] = z[2];
	(*countY)++;
}

// OK
int mpc_AND_verify(
		const uint32_t x[2],
		const uint32_t y[2],
		uint32_t z[2],
		const View ve, const View ve1,
		const unsigned char *randomness[2],
		int* randCount,
		int* countY) {
	uint32_t r[2] = { getRandom32(randomness[0], *randCount), getRandom32(randomness[1], *randCount) };
	*randCount += 4;

	uint32_t t = 0;

	t = (x[0] & y[1]) ^ (x[1] & y[0]) ^ (x[0] & y[0]) ^ r[0] ^ r[1];
	if(ve.y[*countY] != t) {
		return 1;
	}
	z[0] = t;
	z[1] = ve1.y[*countY];

	(*countY)++;
	return 0;
}

void mpc_MAJ(
		const uint32_t a[],
		const uint32_t b[3],
		const uint32_t c[3],
		uint32_t z[3] /*OUT*/,
		const unsigned char *randomness[3],
		int* randCount,
		View views[3] /*OUT*/,
		int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	//maj = (a & (b ^ c)) ^ (b & c);
	mpc_XOR(a, b, t0);
	mpc_XOR(a, c, t1);
	mpc_AND(t0, t1, z, randomness, randCount, views, countY);
	mpc_XOR(z, a, z);
}

int mpc_MAJ_verify(
		const uint32_t a[2],
		const uint32_t b[2],
		const uint32_t c[2],
		uint32_t z[3],
		const View ve,
		const View ve1,
		const unsigned char *randomness[2], int* randCount, int* countY) {
	uint32_t t0[3];
	uint32_t t1[3];

	mpc_XOR_verify(a, b, t0);
	mpc_XOR_verify(a, c, t1);
	if(mpc_AND_verify(t0, t1, z, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR_verify(z, a, z);
	return 0;
}

#endif /* SHARED_H_ */
