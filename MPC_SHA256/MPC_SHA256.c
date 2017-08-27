/*

 Updated by Ivan Pryvalov, 2016
 ============================================================================
 Name        : MPC_SHA256.c
 Author      : Sobuno
 Version     : 0.1
 Description : MPC SHA256 for one block only
 ============================================================================
 */
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "omp.h"


//#define ENABLE_OMP_PARALLEL_FOR

// #error ySize was already defined
#define ySize 736
#include "shared.h"


static const uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

static const uint32_t k[64] = { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
		0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
		0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
		0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6,
		0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3,
		0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
		0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
		0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
		0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
		0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
		0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814,
		0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

#define CH(e,f,g) ((e & f) ^ ((~e) & g))


int totalRandom = 0;
int totalSha = 0;
int totalSS = 0;
int totalHash = 0;


//void print_array(char * msg, char * buf, int count){
//	printf("%s = ", msg);
//	for(int i=0; i<10; i++){
//		printf("%X ", buf[i] & 255);
//	}
//	printf ("...");
//	for(int i=count-10; i<count; i++){
//		printf("%X ", buf[i] & 255);
//	}
//	printf("\n");
//}


/*
int sha256(unsigned char* result, unsigned char* input, int numBits) {
	uint32_t hA[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
			0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };


	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}
	int chars = numBits >> 3;
	unsigned char* chunk = calloc(64, 1); //512 bits
	memcpy(chunk, input, chars);
	chunk[chars] = 0x80;
	//Last 8 chars used for storing length of input without padding, in big-endian.
	//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

	//chunk[60] = numBits >> 24;
	//chunk[61] = numBits >> 16;
	chunk[62] = numBits >> 8;
	chunk[63] = numBits;

	uint32_t w[64];
	int i;
	for (i = 0; i < 16; i++) {
		w[i] = (chunk[i * 4] << 24) | (chunk[i * 4 + 1] << 16)
						| (chunk[i * 4 + 2] << 8) | chunk[i * 4 + 3];
	}

	uint32_t s0, s1;
	for (i = 16; i < 64; i++) {
		s0 = RIGHTROTATE(w[i - 15], 7) ^ RIGHTROTATE(w[i - 15], 18)
						^ (w[i - 15] >> 3);
		s1 = RIGHTROTATE(w[i - 2], 17) ^ RIGHTROTATE(w[i - 2], 19)
						^ (w[i - 2] >> 10);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	uint32_t a, b, c, d, e, f, g, h, temp1, temp2, maj;
	a = hA[0];
	b = hA[1];
	c = hA[2];
	d = hA[3];
	e = hA[4];
	f = hA[5];
	g = hA[6];
	h = hA[7];

	for (i = 0; i < 64; i++) {
		s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e, 11) ^ RIGHTROTATE(e, 25);

		temp1 = h + s1 + CH(e, f, g) + k[i] + w[i];
		s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a, 13) ^ RIGHTROTATE(a, 22);


		maj = (a & (b ^ c)) ^ (b & c);
		temp2 = s0 + maj;


		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;

	}

	hA[0] += a;
	hA[1] += b;
	hA[2] += c;
	hA[3] += d;
	hA[4] += e;
	hA[5] += f;
	hA[6] += g;
	hA[7] += h;

	for (i = 0; i < 8; i++) {
		result[i * 4] = (hA[i] >> 24);
		result[i * 4 + 1] = (hA[i] >> 16);
		result[i * 4 + 2] = (hA[i] >> 8);
		result[i * 4 + 3] = hA[i];
	}
	return 0;
}
*/


void mpc_CH(
		const uint32_t e[],
		const uint32_t f[3],
		const uint32_t g[3],
		uint32_t z[3],
		const unsigned char *randomness[3],
		int* randCount,
		View views[3],
		int* countY) {
	uint32_t t0[3];
	/*
	//t0 = e & f
	mpc_AND(e, f, t0, true);

	//t1 = (~e) & g

	mpc_NEGATE(e, t1);
	mpc_AND(t1, g, t1, true);

	//z = temp1 ^ t1
	mpc_XOR(t0, t1, z);

	 */
	//Alternative, rewritten as e & (f^g) ^ g

	//e & (f^g) ^ g
	mpc_XOR(f,g,t0);
	mpc_AND(e,t0,t0, randomness, randCount, views, countY);
	mpc_XOR(t0,g,z);
}

int mpc_CH_verify(
		const uint32_t e[2],
		const uint32_t f[2],
		const uint32_t g[2],
		uint32_t z[2],
		const View ve,
		const View ve1,
		const unsigned char *randomness[2],
		int* randCount,
		int* countY) {

	uint32_t t0[3];
	mpc_XOR_verify(f,g,t0);
	if(mpc_AND_verify(e, t0, t0, ve, ve1, randomness, randCount, countY) == 1) {
		return 1;
	}
	mpc_XOR_verify(t0,g,z);
	return 0;
}


int mpc_sha256(unsigned char* results[3] /*OUT*/ /*8 words by definition*/,
		const unsigned char* inputs[3] /*IN*/,
		int numBits,
		const unsigned char *randomness[3], View views[3], int* countY) {

	if (numBits > 447) {
		printf("Input too long, aborting!");
		return -1;
	}

	int* randCount = calloc(1, sizeof(int));

	int chars = numBits >> 3;
	unsigned char* chunks[3];
	uint32_t w[64][3];

	for (int i = 0; i < 3; i++) {
		chunks[i] = calloc(64, 1); //512 bits
		memcpy(chunks[i], inputs[i], chars);
		chunks[i][chars] = 0x80;
		//Last 8 chars used for storing length of input without padding, in big-endian.
		//Since we only care for one block, we are safe with just using last 9 bits and 0'ing the rest

		//chunk[60] = numBits >> 24;
		//chunk[61] = numBits >> 16;
		chunks[i][62] = numBits >> 8;
		chunks[i][63] = numBits;
		memcpy(views[i].x, chunks[i], 64);

		for (int j = 0; j < 16; j++) {
			w[j][i] = (chunks[i][j * 4] << 24) | (chunks[i][j * 4 + 1] << 16)
							| (chunks[i][j * 4 + 2] << 8) | chunks[i][j * 4 + 3];
		}
		free(chunks[i]);
	}

	uint32_t s0[3], s1[3];
	uint32_t t0[3], t1[3];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE(w[j-15], 7, t0);

		mpc_RIGHTROTATE(w[j-15], 18, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-15], 3, t1);
		mpc_XOR(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE(w[j-2], 17, t0);
		mpc_RIGHTROTATE(w[j-2], 19, t1);

		mpc_XOR(t0, t1, t0);
		mpc_RIGHTSHIFT(w[j-2], 10, t1);
		mpc_XOR(t0, t1, s1);

		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

		mpc_ADD(w[j-16], s0, t1, randomness, randCount, views, countY);
		mpc_ADD(w[j-7], t1, t1, randomness, randCount, views, countY);
		mpc_ADD(t1, s1, w[j], randomness, randCount, views, countY);

	}

	uint32_t a[3] = { hA[0],hA[0],hA[0] };
	uint32_t b[3] = { hA[1],hA[1],hA[1] };
	uint32_t c[3] = { hA[2],hA[2],hA[2] };
	uint32_t d[3] = { hA[3],hA[3],hA[3] };
	uint32_t e[3] = { hA[4],hA[4],hA[4] };
	uint32_t f[3] = { hA[5],hA[5],hA[5] };
	uint32_t g[3] = { hA[6],hA[6],hA[6] };
	uint32_t h[3] = { hA[7],hA[7],hA[7] };
	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE(e, 6, t0);
		mpc_RIGHTROTATE(e, 11, t1);
		mpc_XOR(t0, t1, t0);

		mpc_RIGHTROTATE(e, 25, t1);
		mpc_XOR(t0, t1, s1);


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		mpc_ADD(h, s1, t0, randomness, randCount, views, countY);


		mpc_CH(e, f, g, t1, randomness, randCount, views, countY);

		//t1 = t0 + t1 (h+s1+ch)
		mpc_ADD(t0, t1, t1, randomness, randCount, views, countY);

		mpc_ADDK(t1, k[i], t1, randomness, randCount, views, countY);

		mpc_ADD(t1, w[i], temp1, randomness, randCount, views, countY);

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE(a, 2, t0);
		mpc_RIGHTROTATE(a, 13, t1);
		mpc_XOR(t0, t1, t0);
		mpc_RIGHTROTATE(a, 22, t1);
		mpc_XOR(t0, t1, s0);


		mpc_MAJ(a, b, c, maj, randomness, randCount, views, countY);

		//temp2 = s0+maj;
		mpc_ADD(s0, maj, temp2, randomness, randCount, views, countY);

		memcpy(h, g, sizeof(uint32_t) * 3);
		memcpy(g, f, sizeof(uint32_t) * 3);
		memcpy(f, e, sizeof(uint32_t) * 3);
		//e = d+temp1;
		mpc_ADD(d, temp1, e, randomness, randCount, views, countY);
		memcpy(d, c, sizeof(uint32_t) * 3);
		memcpy(c, b, sizeof(uint32_t) * 3);
		memcpy(b, a, sizeof(uint32_t) * 3);
		//a = temp1+temp2;

		mpc_ADD(temp1, temp2, a, randomness, randCount, views, countY);
	}

	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
	//hHa[0] = hA[0] + a
	mpc_ADD(hHa[0], a, hHa[0], randomness, randCount, views, countY);
	mpc_ADD(hHa[1], b, hHa[1], randomness, randCount, views, countY);
	mpc_ADD(hHa[2], c, hHa[2], randomness, randCount, views, countY);
	mpc_ADD(hHa[3], d, hHa[3], randomness, randCount, views, countY);
	mpc_ADD(hHa[4], e, hHa[4], randomness, randCount, views, countY);
	mpc_ADD(hHa[5], f, hHa[5], randomness, randCount, views, countY);
	mpc_ADD(hHa[6], g, hHa[6], randomness, randCount, views, countY);
	mpc_ADD(hHa[7], h, hHa[7], randomness, randCount, views, countY);

	for (int i = 0; i < 8; i++) {
		mpc_RIGHTSHIFT(hHa[i], 24, t0);
		results[0][i * 4] = t0[0];
		results[1][i * 4] = t0[1];
		results[2][i * 4] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 16, t0);
		results[0][i * 4 + 1] = t0[0];
		results[1][i * 4 + 1] = t0[1];
		results[2][i * 4 + 1] = t0[2];
		mpc_RIGHTSHIFT(hHa[i], 8, t0);
		results[0][i * 4 + 2] = t0[0];
		results[1][i * 4 + 2] = t0[1];
		results[2][i * 4 + 2] = t0[2];

		results[0][i * 4 + 3] = hHa[i][0];
		results[1][i * 4 + 3] = hHa[i][1];
		results[2][i * 4 + 3] = hHa[i][2];
	}
	free(randCount);
	return 0;
}


int mpc_SHA256_verify(a a, int e, z z) {
	int outputWordsCnt = 8; // 256 bit // FIXME
	int outputBytes = outputWordsCnt << 2;


	unsigned char* hash = malloc(SHA256_DIGEST_LENGTH);
	H(hash, z.ke, z.ve, z.re);

	if (memcmp(a.h[e], hash, outputBytes) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	H(hash, z.ke1, z.ve1, z.re1);
	if (memcmp(a.h[(e + 1) % 3], hash, outputBytes) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	free(hash);

	//FIXME do we need it? View does not keep yp[]
	uint32_t* result = malloc(outputBytes);
	output(result, z.ve, outputWordsCnt);
	if (memcmp(a.yp[e], result, outputBytes) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	output(result, z.ve1, outputWordsCnt);
	if (memcmp(a.yp[(e + 1) % 3], result, outputBytes) != 0) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	free(result);

	const int randomnessBits = 728*32;
	const int randomnessBytes = randomnessBits >> 3; // + 1?
	//= 2912
	//unsigned char randomness[2][2912];
	unsigned char *randomness[2];
	for(int i=0; i<2; i++)
		randomness[i] = calloc(randomnessBytes, sizeof(unsigned char));
	getAllRandomness(z.ke, randomness[0], randomnessBits); // FIXME read input seed from the proof.
	getAllRandomness(z.ke1, randomness[1], randomnessBits);

	int* randCount = calloc(1, sizeof(int));
	int* countY = calloc(1, sizeof(int));

	uint32_t w[64][2];
	for (int j = 0; j < 16; j++) {
		w[j][0] = (z.ve.x[j * 4] << 24) | (z.ve.x[j * 4 + 1] << 16)
								| (z.ve.x[j * 4 + 2] << 8) | z.ve.x[j * 4 + 3];
		w[j][1] = (z.ve1.x[j * 4] << 24) | (z.ve1.x[j * 4 + 1] << 16)
								| (z.ve1.x[j * 4 + 2] << 8) | z.ve1.x[j * 4 + 3];
	}

	uint32_t s0[2], s1[2];
	uint32_t t0[2], t1[2];
	for (int j = 16; j < 64; j++) {
		//s0[i] = RIGHTROTATE(w[i][j-15],7) ^ RIGHTROTATE(w[i][j-15],18) ^ (w[i][j-15] >> 3);
		mpc_RIGHTROTATE_verify(w[j-15], 7, t0);
		mpc_RIGHTROTATE_verify(w[j-15], 18, t1);
		mpc_XOR_verify(t0, t1, t0);
		mpc_RIGHTSHIFT_verify(w[j-15], 3, t1);
		mpc_XOR_verify(t0, t1, s0);

		//s1[i] = RIGHTROTATE(w[i][j-2],17) ^ RIGHTROTATE(w[i][j-2],19) ^ (w[i][j-2] >> 10);
		mpc_RIGHTROTATE_verify(w[j-2], 17, t0);
		mpc_RIGHTROTATE_verify(w[j-2], 19, t1);
		mpc_XOR_verify(t0, t1, t0);
		mpc_RIGHTSHIFT_verify(w[j-2],10,t1);
		mpc_XOR_verify(t0, t1, s1);

		//w[i][j] = w[i][j-16]+s0[i]+w[i][j-7]+s1[i];

		if(mpc_ADD_verify(w[j-16], s0, t1, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}


		if(mpc_ADD_verify(w[j-7], t1, t1, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}
		if(mpc_ADD_verify(t1, s1, w[j], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, j);
#endif
			return 1;
		}
	}

	uint32_t va[2] = { hA[0],hA[0] };
	uint32_t vb[2] = { hA[1],hA[1] };
	uint32_t vc[2] = { hA[2],hA[2] };
	uint32_t vd[2] = { hA[3],hA[3] };
	uint32_t ve[2] = { hA[4],hA[4] };
	uint32_t vf[2] = { hA[5],hA[5] };
	uint32_t vg[2] = { hA[6],hA[6] };
	uint32_t vh[2] = { hA[7],hA[7] };
	uint32_t temp1[3], temp2[3], maj[3];
	for (int i = 0; i < 64; i++) {
		//s1 = RIGHTROTATE(e,6) ^ RIGHTROTATE(e,11) ^ RIGHTROTATE(e,25);
		mpc_RIGHTROTATE_verify(ve, 6, t0);
		mpc_RIGHTROTATE_verify(ve, 11, t1);
		mpc_XOR_verify(t0, t1, t0);
		mpc_RIGHTROTATE_verify(ve, 25, t1);
		mpc_XOR_verify(t0, t1, s1);


		//ch = (e & f) ^ ((~e) & g);
		//temp1 = h + s1 + CH(e,f,g) + k[i]+w[i];

		//t0 = h + s1

		if(mpc_ADD_verify(vh, s1, t0, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		if(mpc_CH_verify(ve, vf, vg, t1, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//t1 = t0 + t1 (h+s1+ch)
		if(mpc_ADD_verify(t0, t1, t1, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		t0[0] = k[i];
		t0[1] = k[i];
		if(mpc_ADD_verify(t1, t0, t1, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		if(mpc_ADD_verify(t1, w[i], temp1, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//s0 = RIGHTROTATE(a,2) ^ RIGHTROTATE(a,13) ^ RIGHTROTATE(a,22);
		mpc_RIGHTROTATE_verify(va, 2, t0);
		mpc_RIGHTROTATE_verify(va, 13, t1);
		mpc_XOR_verify(t0, t1, t0);
		mpc_RIGHTROTATE_verify(va, 22, t1);
		mpc_XOR_verify(t0, t1, s0);

		//maj = (a & (b ^ c)) ^ (b & c);
		//(a & b) ^ (a & c) ^ (b & c)

		if(mpc_MAJ_verify(va, vb, vc, maj, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		//temp2 = s0+maj;
		if(mpc_ADD_verify(s0, maj, temp2, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}



		memcpy(vh, vg, sizeof(uint32_t) * 2);
		memcpy(vg, vf, sizeof(uint32_t) * 2);
		memcpy(vf, ve, sizeof(uint32_t) * 2);
		//e = d+temp1;
		if(mpc_ADD_verify(vd, temp1, ve, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}

		memcpy(vd, vc, sizeof(uint32_t) * 2);
		memcpy(vc, vb, sizeof(uint32_t) * 2);
		memcpy(vb, va, sizeof(uint32_t) * 2);
		//a = temp1+temp2;

		if(mpc_ADD_verify(temp1, temp2, va, z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d, iteration %d", __LINE__, i);
#endif
			return 1;
		}
	}

	uint32_t hHa[8][3] = { { hA[0],hA[0],hA[0]  }, { hA[1],hA[1],hA[1] }, { hA[2],hA[2],hA[2] }, { hA[3],hA[3],hA[3] },
			{ hA[4],hA[4],hA[4] }, { hA[5],hA[5],hA[5] }, { hA[6],hA[6],hA[6] }, { hA[7],hA[7],hA[7] } };
	if(mpc_ADD_verify(hHa[0], va, hHa[0], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[1], vb, hHa[1], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[2], vc, hHa[2], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[3], vd, hHa[3], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[4], ve, hHa[4], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[5], vf, hHa[5], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[6], vg, hHa[6], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}
	if(mpc_ADD_verify(hHa[7], vh, hHa[7], z.ve, z.ve1, (const unsigned char**) randomness, randCount, countY) == 1) {
#if VERBOSE
		printf("Failing at %d", __LINE__);
#endif
		return 1;
	}

	//FIXME check result[2] ??

	free(randCount);
	free(countY);
	for(int i=0; i<2; i++)
		free(randomness[i]);

	return 0;
}


/*
int writeToFile(char filename[], void* data, int size, int numItems) {
	FILE *file;

	file = fopen(filename, "wb");
	if (!file) {
		printf("Unable to open file!");
		return 1;
	}
	fwrite(data, size, numItems, file);
	fclose(file);
	return 0;
}*/


int secretShare(unsigned char* input, int numBytes, unsigned char output[3][numBytes]) {
	if(RAND_bytes(output[0], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	if(RAND_bytes(output[1], numBytes) != 1) {
		printf("RAND_bytes failed crypto, aborting\n");
	}
	for (int j = 0; j < numBytes; j++) {
		output[2][j] = input[j] ^ output[0][j] ^ output[1][j];
	}
	return 0;
}


// "SHA-1" = 5 words = 160 bits
// "SHA-256" = 8 words = 256 bits
// a.yp[3][8] is filled in.
a commit(int numBytes,
		unsigned char shares[3][numBytes],
		const unsigned char *randomness[3],
		View views[3],
		int resultWords /*1 word = 4 bytes = 32 bits*/) {

	unsigned char* inputs[3];
	for(int party=0; party<3; party++)
		inputs[party] = shares[party];
	unsigned char* hashes[3]; //[3][32]
	for(int party=0; party<3; party++)
		hashes[party] = malloc(resultWords << 2); // bytes = words * 4
	int* countY = calloc(1, sizeof(int));
	//hashes is 8 * 4 words = 32 bytes = 256 bits;
	mpc_sha256(hashes, (const unsigned char**)inputs, numBytes * 8, randomness, views, countY);

	//Explicitly add y to view a number of words (e.g., 8 for SHA-256) ??
	for(int i = 0; i<resultWords; i++) {
		for(int party=0; party<3; party++)
			// write 1 word / 4 bytes //FIXME why just 1 word?
			views[party].y[*countY] = (hashes[party][i * 4] << 24) | (hashes[party][i * 4 + 1] << 16)
					| (hashes[party][i * 4 + 2] << 8) | hashes[party][i * 4 + 3];
		*countY += 1;
	}
	free(countY);
	for(int party=0; party<3; party++)
		free(hashes[party]);

	uint32_t* result[3];
	for(int party=0; party<3; party++){
		result[party] = malloc(resultWords << 2);
		output(result[party], views[party], resultWords);
	}

	a a;
	for(int party=0; party<3; party++)
		memcpy(a.yp[party], result[party], resultWords << 2);
	for(int party=0; party<3; party++)
		free(result[party]);
	return a;
}


z prove(int e /*0..2*/,
		const unsigned char keys[3][16] /*IN*/,
		const unsigned char rs[3][4]/*IN*/,
		const View views[3]/*IN*/) {
	z z;
	memcpy(z.ke, keys[e], 16);
	memcpy(z.ke1, keys[(e + 1) % 3], 16);
	z.ve = views[e];
	z.ve1 = views[(e + 1) % 3];
	memcpy(z.re, rs[e],4);
	memcpy(z.re1, rs[(e + 1) % 3],4);

	return z;
}

void fail_RAND_bytes(){
	printf("RAND_bytes failed crypto, aborting\n");
	exit(EXIT_FAILURE);
}


void store_data(char *buffer, int buffer_size,
		const a *as, const z *zs, int count){
	int offset = sizeof(a) * count;
	int offset2 = sizeof(z) * count;
	if (offset + offset2 > buffer_size){
		printf("buffer for storing data is too small");
		exit(EXIT_FAILURE);
	}
	memcpy(buffer, as, offset);
	memcpy(buffer + offset, zs, offset2);
}


void load_data(a *as, z *zs, int count, const char *buffer, int buffer_size){
	int offset = sizeof(a) * count;
	int offset2 = sizeof(z) * count;
	if (offset + offset2 > buffer_size){
		printf("buffer for loading data is too small");
		exit(EXIT_FAILURE);
	}
	memcpy(as, (void*) buffer, offset);
	memcpy(zs, (void*) (buffer + offset), offset2);
}


void run_one_iteration_prover(int iteration_number, char buffer[], int buffer_size,
		const char outputFile[], const char userInput[55]){
	const int outputWords = 8;
	//const int outputBits = outputWords * 4 * 8; // FIXME

	printf("Running prover...\n");
	//
	unsigned char garbage[4];
	if(RAND_bytes(garbage, 4) != 1)
		fail_RAND_bytes();

	int inputLen = strlen(userInput)-1;
	printf("String length: %d\n", inputLen);

	printf("Iterations of SHA: %d\n", NUM_ROUNDS);

	unsigned char input[inputLen];
	for(int i = 0; i<inputLen; i++) {
		input[i] = userInput[i];
	}

	clock_t begin = clock();
	unsigned char rs[NUM_ROUNDS][3][4];
	unsigned char keys[NUM_ROUNDS][3][16];
	a as[NUM_ROUNDS];
	View localViews[NUM_ROUNDS][3];
	int totalCrypto = 0;

	//Generating keys
	clock_t beginCrypto = clock();
	if(RAND_bytes((unsigned char *)keys, NUM_ROUNDS*3*16) != 1)
		fail_RAND_bytes();
	if(RAND_bytes((unsigned char *)rs, NUM_ROUNDS*3*4) != 1)
		fail_RAND_bytes();
	totalCrypto = measure(&beginCrypto);


	//Sharing secrets
	   //--- it is random values that XOR all together to INPUT
	clock_t beginSS = clock();
	unsigned char shares[NUM_ROUNDS][3][inputLen];
	if(RAND_bytes((unsigned char *)shares, NUM_ROUNDS*3*inputLen) != 1)
		fail_RAND_bytes();
#ifdef ENABLE_OMP_PARALLEL_FOR
	#pragma omp parallel for
#endif
	for(int k=0; k<NUM_ROUNDS; k++) {
		for (int j = 0; j < inputLen; j++) {
			shares[k][2][j] = input[j] ^ shares[k][0][j] ^ shares[k][1][j];
		}
	}
	totalSS = measure(&beginSS);

	//Generating randomness
	int randomnessBytes = 2912; //FIXME
	clock_t beginRandom = clock();
	unsigned char *randomness[NUM_ROUNDS][3];
#ifdef ENABLE_OMP_PARALLEL_FOR
	#pragma omp parallel for
#endif
	for(int k=0; k<NUM_ROUNDS; k++) {
		for(int j = 0; j<3; j++) {
			randomness[k][j] = malloc(randomnessBytes*sizeof(unsigned char));
			getAllRandomness(keys[k][j], randomness[k][j], randomnessBytes << 3); // via AES
		}
	}
	totalRandom = measure(&beginRandom);// inMilli;

	//Running MPC-SHA2
	clock_t beginSha = clock();
#ifdef ENABLE_OMP_PARALLEL_FOR
	#pragma omp parallel for
#endif
	for(int k=0; k<NUM_ROUNDS; k++) {
		as[k] = commit(inputLen, shares[k], (const unsigned char **)randomness[k], localViews[k], outputWords);
		//as[k].yp is set
		//as[k].h is not yet set
		for(int j=0; j<3; j++) {
			free(randomness[k][j]);
		}
	}
	totalSha = measure(&beginSha);

	//Committing
	clock_t beginHash = clock();
#ifdef ENABLE_OMP_PARALLEL_FOR
	#pragma omp parallel for
#endif
	for(int k=0; k<NUM_ROUNDS; k++) {
		unsigned char hash1[SHA256_DIGEST_LENGTH];
		for(int party=0; party<3; party++){
			H((unsigned char *) &hash1, keys[k][party], localViews[k][party], rs[k][party]);
			memcpy(as[k].h[party], (unsigned char *) &hash1, 32);
		}
	}
	totalHash += measure(&beginHash);//inMilli;

	int inMilliA = measure(&begin);

	//Generating E
	clock_t beginE = clock();
	int es[NUM_ROUNDS];
	uint32_t finalHash[8];
	for (int j = 0; j < 8; j++) {
		finalHash[j] = as[0].yp[0][j]^as[0].yp[1][j]^as[0].yp[2][j]; // y = Rec(y1..y3)
	}
	H3(es, finalHash, as, NUM_ROUNDS);
	int inMilliE = measure(&beginE);


	//Packing Z
	clock_t beginZ = clock();
	z* zs = malloc(sizeof(z)*NUM_ROUNDS);

#ifdef ENABLE_OMP_PARALLEL_FOR
	#pragma omp parallel for
#endif
	for(int i = 0; i<NUM_ROUNDS; i++) {
		zs[i] = prove(es[i],keys[i],rs[i], localViews[i]);
	}
	int inMilliZ = measure(&beginZ);


	//Writing to file
	clock_t beginWrite = clock();
	FILE *file;

	int inMilliWrite = -1;
	if (outputFile){
		file = fopen(outputFile, "wb");
		if (!file) {
			printf("Unable to open file %s!\n", outputFile);
			exit(EXIT_FAILURE);
		}
		fwrite(as, sizeof(a), NUM_ROUNDS, file);
		fwrite(zs, sizeof(z), NUM_ROUNDS, file);
		fclose(file);
	}
	store_data(buffer, buffer_size, as, zs, NUM_ROUNDS);
	inMilliWrite = measure(&beginWrite);

	free(zs);

	int totalTime = measure(&begin);

	int sumOfParts = 0;

	printf("Generating A: %ju\n", (uintmax_t)inMilliA);
	printf("	Generating keys: %ju\n", (uintmax_t)totalCrypto);
	sumOfParts += totalCrypto;
	printf("	Generating randomness: %ju\n", (uintmax_t)totalRandom);
	sumOfParts += totalRandom;
	printf("	Sharing secrets: %ju\n", (uintmax_t)totalSS);
	sumOfParts += totalSS;
	printf("	Running MPC-SHA2: %ju\n", (uintmax_t)totalSha);
	sumOfParts += totalSha;
	printf("	Committing: %ju\n", (uintmax_t)totalHash);
	sumOfParts += totalHash;
	printf("	*Accounted for*: %ju\n", (uintmax_t)sumOfParts);
	printf("Generating E: %ju\n", (uintmax_t)inMilliE);
	printf("Packing Z: %ju\n", (uintmax_t)inMilliZ);
	printf("Writing file: %ju\n", (uintmax_t)inMilliWrite);
	printf("Total: %d\n",totalTime);
	printf("\n");
	printf("Proof output to file %s\n", outputFile);

}


void run_one_iteration_verifier(int iterationNummer, char buffer[], int buffer_size,
		const char inputFile[]){
	printf("Running verifier...\n");
	printf("Iterations of SHA: %d\n", NUM_ROUNDS);

	clock_t begin = clock();

	a as[NUM_ROUNDS];
	z zs[NUM_ROUNDS];
	FILE *file;

	if (inputFile){
		file = fopen(inputFile, "rb");
		if (!file) {
			printf("Unable to open file %s!\n", inputFile);
		}
		if (fread(&as, sizeof(a), NUM_ROUNDS, file) != NUM_ROUNDS){
			printf("Could not read a[%d]", NUM_ROUNDS);
			exit(EXIT_FAILURE);
		}
		if (fread(&zs, sizeof(z), NUM_ROUNDS, file) != NUM_ROUNDS){
			printf("Could not read z[%d]", NUM_ROUNDS);
			exit(EXIT_FAILURE);
		}
		fclose(file);
	}else{
		load_data(as, zs, NUM_ROUNDS, buffer, buffer_size);
	}

	uint32_t y[8];
	reconstruct(as[0].yp[0],as[0].yp[1],as[0].yp[2],y);
	printf("Proof for hash (verifier): ");
	for(int i=0;i<8;i++) { //FIXME should be 5 for SHA1?
		printf("%02X", y[i]);
	}
	printf("\n");

	int inMilliFiles = measure(&begin);
	printf("Loading files: %ju\n", (uintmax_t)inMilliFiles);


	clock_t beginE = clock();
	int es[NUM_ROUNDS];
	H3(es, y, as, NUM_ROUNDS);
	int inMilliE = measure(&beginE);
	printf("Generating E: %ju\n", (uintmax_t)inMilliE);


	clock_t beginV = clock();
#ifdef ENABLE_OMP_PARALLEL_FOR
	#pragma omp parallel for
#endif
	for(int i = 0; i<NUM_ROUNDS; i++) {
		int verifyResult = mpc_SHA256_verify(as[i], es[i], zs[i]);
		if (verifyResult != 0) {
			printf("Not Verified %d\n", i);
		}
	}
	int inMilliV = measure(&beginV);
	printf("Verifying: %ju\n", (uintmax_t)inMilliV);

	int inMilli = measure(&begin);
	printf("Total time: %ju\n", (uintmax_t)inMilli);
	printf("File %s verified\n", inputFile);

}

int main(int argc, char *argv[]) {
	if (argc<=1){
		printf("command line parameters:\n");
		printf("\t -p                  If specified, run the prover (by default, no)\n");
		printf("\t -v                  If specified, run the verifier (by default, no)\n");
		printf("\t -stdin              Read input from stdin (if not specified, it will be generated automatically)\n");
		printf("\t -file               Enable disk operations, e.g. writing proofs to file, or reading proofs from file (by default disabled)\n");
		printf("\t iterations          Number of iterations (by default, 1)\n");
		exit(0);
	}
	
	setbuf(stdout, NULL);
	srand((unsigned) time(NULL)); //?
	init_EVP();
	openmp_thread_setup();

	int repetitions = 1;
	int run_prover = 0;
	int run_verifier = 0;
	int standard_in = 0;
	int disk_operations = 0;

	// parse command line arguments.
	// =>  -p     Run the prover
	// =>  -v     Run the verifier
	// =>  1000   Number of iterations
	for(int i=1; i<argc; i++){
		if (argv[i][0] == '-'){
			if (strcmp(&argv[i][1],"p")==0)
				run_prover = 1;
			if (strcmp(&argv[i][1],"v")==0)
				run_verifier = 1;
			if (strcmp(&argv[i][1],"stdin")==0)
				standard_in = 1;
			if (strcmp(&argv[i][1],"file")==0)
				disk_operations = 1;

		}else{
			sscanf(argv[i], "%d", &repetitions);
			printf("Repetitions = %d", repetitions);
		}
	}

	int buffer_size = 1024 * 1024;
	char file_in_memory[buffer_size];
	for(int iter=0; iter<repetitions; iter++){
		char filename[255];
		if (disk_operations != 0)
			sprintf(filename, "data/out%i.bin.%i", NUM_ROUNDS, iter);
		if (run_prover){
			char userInput[55]; //55 is max length as we only support 447 bits = 55.875 bytes
			if (standard_in != 0){
				printf("Enter the string to be hashed (Max 55 characters): ");
				if (fgets(userInput, sizeof(userInput), stdin)==NULL){
					exit(EXIT_FAILURE);
				}
			}else{
				for(int i=0; i<55; i++){
					userInput[i] = (rand() % (0x7D - 0x21)) + 0x21;
				}
				userInput[54] = 0;
				printf("User input for iteration %d = %s\n", iter, userInput);
			}
			run_one_iteration_prover(iter, file_in_memory, buffer_size,
					disk_operations? filename : NULL,
					userInput);
		}
		if (run_verifier){
			//run verifier
			run_one_iteration_verifier(iter, file_in_memory, buffer_size,
					disk_operations? filename : NULL);
		}
		memset(file_in_memory, 0, buffer_size);
	}

	openmp_thread_cleanup();
	cleanup_EVP();
	return EXIT_SUCCESS;
}
