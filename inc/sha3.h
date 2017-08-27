// Reference source code can be found at https://github.com/brainhub/SHA3IUF, it was cloned on August 26, 2016.
/* -------------------------------------------------------------------------
 * Works when compiled for either 32-bit or 64-bit targets, optimized for 
 * 64 bit.
 *
 * Canonical implementation of Init/Update/Finalize for SHA-3 byte input. 
 *
 * SHA3-256, SHA3-384, SHA-512 are implemented. SHA-224 can easily be added.
 *
 * Based on code from http://keccak.noekeon.org/ .
 *
 * I place the code that I wrote into public domain, free to use. 
 *
 * I would appreciate if you give credits to this work if you used it to 
 * write or test your code.
 *
 * Aug 2015. Andrey Jivsov. crypto@brainhub.org
 * ---------------------------------------------------------------------- */

#ifndef INC_SHA3_H_
#define INC_SHA3_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "assert.h"
#include "mpc_types.h"

#define SHA3_ASSERT( x ) assert(x);
#if defined(_MSC_VER)
#define SHA3_TRACE( format, ...)
#define SHA3_TRACE_BUF( format, buf, l, ...)
#else
#define SHA3_TRACE(format, args...)
#define SHA3_TRACE_BUF(format, buf, l, args...)
#endif

//#define SHA3_USE_KECCAK
/* 
 * Define SHA3_USE_KECCAK to run "pure" Keccak, as opposed to SHA3.
 * The tests that this macro enables use the input and output from [Keccak]
 * (see the reference below). The used test vectors aren't correct for SHA3, 
 * however, they are helpful to verify the implementation.
 * SHA3_USE_KECCAK only changes one line of code in Finalize.
 */

#if defined(_MSC_VER)
#define SHA3_CONST(x) x
#else
#define SHA3_CONST(x) x##L
#endif

/* The following state definition should normally be in a separate 
 * header file 
 */

/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8/*bits to byte*/)/sizeof(uint64_t))
template <typename T> //e.g. uint64_t or MpcVariable<uint64_t>
struct sha3_context {
    T saved;             /* the portion of the input message that we
                                 * didn't consume yet */
//    union {                     /* Keccak's state */
//        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
//        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
//    };
    T s[SHA3_KECCAK_SPONGE_WORDS];
    unsigned byteIndex;         /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
    unsigned wordIndex;         /* 0..24--the next word to integrate input
                                 * (starts from 0) */
    unsigned capacityWords;     /* the double size of the hash output in
                                 * words (e.g. 16 for Keccak 512) */
};

/*#ifndef SHA3_ROTL64
#define SHA3_ROTL64(x, y) \
	(((x) << (y)) | ((x) >> ((sizeof(uint64_t)*8) - (y))))
#endif*/

static const uint64_t keccakf_rndc[24] = {
    SHA3_CONST(0x0000000000000001UL), SHA3_CONST(0x0000000000008082UL),
    SHA3_CONST(0x800000000000808aUL), SHA3_CONST(0x8000000080008000UL),
    SHA3_CONST(0x000000000000808bUL), SHA3_CONST(0x0000000080000001UL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008009UL),
    SHA3_CONST(0x000000000000008aUL), SHA3_CONST(0x0000000000000088UL),
    SHA3_CONST(0x0000000080008009UL), SHA3_CONST(0x000000008000000aUL),
    SHA3_CONST(0x000000008000808bUL), SHA3_CONST(0x800000000000008bUL),
    SHA3_CONST(0x8000000000008089UL), SHA3_CONST(0x8000000000008003UL),
    SHA3_CONST(0x8000000000008002UL), SHA3_CONST(0x8000000000000080UL),
    SHA3_CONST(0x000000000000800aUL), SHA3_CONST(0x800000008000000aUL),
    SHA3_CONST(0x8000000080008081UL), SHA3_CONST(0x8000000000008080UL),
    SHA3_CONST(0x0000000080000001UL), SHA3_CONST(0x8000000080008008UL)
};

static const unsigned keccakf_rotc[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62,
    18, 39, 61, 20, 44
};

static const unsigned keccakf_piln[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20,
    14, 22, 9, 6, 1
};

/* generally called after SHA3_KECCAK_SPONGE_WORDS-ctx->capacityWords words 
 * are XORed into the state s 
 */
template <typename T>
void
keccakf(T s[25])
{
    int i, j, round;
    T t, bc[5];
#define KECCAK_ROUNDS 24

    for(round = 0; round < KECCAK_ROUNDS; round++) {

        /* Theta */
        for(i = 0; i < 5; i++)
            bc[i] = s[i] ^ s[i + 5] ^ s[i + 10] ^ s[i + 15] ^ s[i + 20];

        for(i = 0; i < 5; i++) {
        	t = bc[(i + 4) % 5] ^ _rotateleft(bc[(i + 1) % 5], 1);
            for(j = 0; j < 25; j += 5)
                s[j + i] ^= t;
        }

        /* Rho Pi */
        t = s[1];
        for(i = 0; i < 24; i++) {
            j = keccakf_piln[i];
            bc[0] = s[j];
            s[j] = _rotateleft(t, keccakf_rotc[i]);
            t = bc[0];
        }

        /* Chi */
        for(j = 0; j < 25; j += 5) {
            for(i = 0; i < 5; i++)
                bc[i] = s[j + i];
            for(i = 0; i < 5; i++)
                s[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
        }

        /* Iota */
        s[0] ^= keccakf_rndc[round];
    }
}

/* *************************** Public Inteface ************************ */

/* For Init or Reset call these: */
template <typename T>
void
sha3_Init(sha3_context<T> *ctx){
	//memset(ctx, 0, sizeof(*ctx)); //this does not work when T=MpcVariable
	ctx->saved = 0;
	for(unsigned int i=0; i<SHA3_KECCAK_SPONGE_WORDS; i++){
		ctx->s[i] = 0;
	}
	ctx->byteIndex = 0;
	ctx->wordIndex = 0;
}


template <typename T>
void
sha3_Init256(sha3_context<T> *ctx)
{
	sha3_Init(ctx);
    ctx->capacityWords = 2 * 256 / (8 * sizeof(uint64_t));
}

template <typename T>
void
sha3_Init384(sha3_context<T> *ctx)
{
	sha3_Init(ctx);
    ctx->capacityWords = 2 * 384 / (8 * sizeof(uint64_t));
}

template <typename T>
void
sha3_Init512(sha3_context<T> *ctx)
{
	sha3_Init(ctx);
    ctx->capacityWords = 2 * 512 / (8 * sizeof(uint64_t));
}

template <typename T8, typename T64>
void
sha3_Update(sha3_context<T64> *ctx, const T8 *buf, size_t len /*bytes*/)
{
    /* 0...7 -- how much is needed to have a word */
    unsigned old_tail = (8 - ctx->byteIndex) & 7;

    size_t words;
    unsigned tail;
    size_t i;

    SHA3_TRACE_BUF("called to update with:", buf, len);

    SHA3_ASSERT(ctx->byteIndex < 8);
    //SHA3_ASSERT(ctx->wordIndex < sizeof(ctx->s) / sizeof(ctx->s[0])); //won't work for MpcVariable

    if(len < old_tail) {        /* have no complete word or haven't started 
                                 * the word yet */
        SHA3_TRACE("because %d<%d, store it and return", (unsigned)len,
                (unsigned)old_tail);
        /* endian-independent code follows: */
        while (len--)
            ctx->saved |= (T64) (*(buf++)) << ((ctx->byteIndex++) * 8);
        SHA3_ASSERT(ctx->byteIndex < 8);
        return;
    }

    if(old_tail) {              /* will have one word to process */
        SHA3_TRACE("completing one word with %d bytes", (unsigned)old_tail);
        /* endian-independent code follows: */
        len -= old_tail;
        while (old_tail--)
            ctx->saved |= (T64) (*(buf++)) << ((ctx->byteIndex++) * 8);

        /* now ready to add saved to the sponge */
        ctx->s[ctx->wordIndex] ^= ctx->saved;
        SHA3_ASSERT(ctx->byteIndex == 8);
        ctx->byteIndex = 0;
        ctx->saved = 0;
        if(++ctx->wordIndex ==
                (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
            keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    /* now work in full words directly from input */

    SHA3_ASSERT(ctx->byteIndex == 0);

    words = len / sizeof(uint64_t);
    tail = len - words * sizeof(uint64_t);

    SHA3_TRACE("have %d full words to process", (unsigned)words);

    for(i = 0; i < words; i++, buf += sizeof(uint64_t)) {
        const T64 t = (T64) (buf[0]) |
                ((T64) (buf[1]) << 8 * 1) |
                ((T64) (buf[2]) << 8 * 2) |
                ((T64) (buf[3]) << 8 * 3) |
                ((T64) (buf[4]) << 8 * 4) |
                ((T64) (buf[5]) << 8 * 5) |
                ((T64) (buf[6]) << 8 * 6) |
                ((T64) (buf[7]) << 8 * 7);
#if defined(__x86_64__ ) || defined(__i386__)
        //SHA3_ASSERT(memcmp(&t, buf, 8) == 0); //FIXME this is not going to work for MpcVariable?
#endif
        ctx->s[ctx->wordIndex] ^= t;
        if(++ctx->wordIndex ==
                (SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords)) {
            keccakf(ctx->s);
            ctx->wordIndex = 0;
        }
    }

    SHA3_TRACE("have %d bytes left to process, save them", (unsigned)tail);

    /* finally, save the partial word */
    SHA3_ASSERT(ctx->byteIndex == 0 && tail < 8);
    while (tail--) {
        SHA3_TRACE("Store byte %02x '%c'", *buf, *buf);
        ctx->saved |= (T64) (*(buf++)) << ((ctx->byteIndex++) * 8);
    }
    SHA3_ASSERT(ctx->byteIndex < 8);
    SHA3_TRACE("Have saved=0x%016" PRIx64 " at the end", ctx->saved);
}

/* This is simply the 'update' with the padding block.
 * The padding block is 0x01 || 0x00* || 0x80. First 0x01 and last 0x80 
 * bytes are always present, but they can be the same byte.
 */
template <typename T64>
T64 const*
sha3_Finalize(sha3_context<T64> *ctx)
{
    SHA3_TRACE("called with %d bytes in the buffer", ctx->byteIndex);

    /* Append 2-bit suffix 01, per SHA-3 spec. Instead of 1 for padding we
     * use 1<<2 below. The 0x02 below corresponds to the suffix 01.
     * Overall, we feed 0, then 1, and finally 1 to start padding. Without
     * M || 01, we would simply use 1 to start padding. */

#ifndef SHA3_USE_KECCAK
    /* SHA3 version */
    ctx->s[ctx->wordIndex] ^=
            (ctx->saved ^ ((T64) ((T64) (0x02 | (1 << 2)) <<
                            ((ctx->byteIndex) * 8))));
#else
    /* For testing the "pure" Keccak version */
    ctx->s[ctx->wordIndex] ^=
            (ctx->saved ^ ((T64) ((T64) 1 << (ctx->byteIndex *
                                    8))));
#endif

    ctx->s[SHA3_KECCAK_SPONGE_WORDS - ctx->capacityWords - 1] ^=
            SHA3_CONST(0x8000000000000000UL);
    keccakf(ctx->s);

    /* Return first bytes of the ctx->s. This conversion is not needed for
     * little-endian platforms e.g. wrap with #if !defined(__BYTE_ORDER__)
     * || !defined(__ORDER_LITTLE_ENDIAN__) || \
     * __BYTE_ORDER__!=__ORDER_LITTLE_ENDIAN__ ... the conversion below ...
     * #endif */
#if !defined(__BYTE_ORDER__) || !defined(__ORDER_LITTLE_ENDIAN__) || \
     __BYTE_ORDER__!=__ORDER_LITTLE_ENDIAN__
    {
        unsigned i;
        for(i = 0; i < SHA3_KECCAK_SPONGE_WORDS; i++) {
            const unsigned t1 = (uint32_t) ctx->s[i];
            const unsigned t2 = (uint32_t) ((ctx->s[i] >> 16) >> 16);
            ctx->sb[i * 8 + 0] = (uint8_t) (t1);
            ctx->sb[i * 8 + 1] = (uint8_t) (t1 >> 8);
            ctx->sb[i * 8 + 2] = (uint8_t) (t1 >> 16);
            ctx->sb[i * 8 + 3] = (uint8_t) (t1 >> 24);
            ctx->sb[i * 8 + 4] = (uint8_t) (t2);
            ctx->sb[i * 8 + 5] = (uint8_t) (t2 >> 8);
            ctx->sb[i * 8 + 6] = (uint8_t) (t2 >> 16);
            ctx->sb[i * 8 + 7] = (uint8_t) (t2 >> 24);
        }
    }
#endif

    //SHA3_TRACE_BUF("Hash: (first 32 bytes)", ctx->sb, 256 / 8));

    //return (ctx->sb);
    return (ctx->s);
}


/*
 * sha3 algorithm for a variable input produces 256 bit of output.
 */
template <typename T8, typename T64>
void sha3_256(
		const T8 input[],
		int len_bytes,
		const uint8_t input_pub[],
		int input_pub_len_bytes,
		T64 output[],
		int output_words){
	assert(output_words == 256/64);

	sha3_context<T64> c;
	const T64 *hash;

	sha3_Init256<T64>(&c); // empty
	sha3_Update(&c, input, len_bytes);
	hash = sha3_Finalize<T64>(&c);
	for(int i=0; i<256/64; i++){
		output[i] = hash[i];
	}
}

/*
 * PRG based on Hash function called HashDRBG. HasGen algorithm is taken generation random bits.
 *
 */
template <typename T8, typename T64>
void sha3_256_DRBG(
		const T8 input[],
		int inputlen_bytes,
		const uint8_t input_pub[],
		int input_pub_len_bytes,
		T64 output[],
		int output_words){
	int output_blocklen = 256/64;
	assert(output_words % output_blocklen == 0);
	unsigned int sha3_iterations = output_words / output_blocklen;

	if (sha3_iterations == 1){
		sha3_256(input, inputlen_bytes, input_pub, input_pub_len_bytes, output, output_blocklen);
	}else{
		int ctr_out = 0;
		for(unsigned int it=0; it<sha3_iterations; it++){
			T64 output1[output_blocklen];
			//append input with bytes i
			T8 input_padded[inputlen_bytes + 4];
			for(int i=0; i<inputlen_bytes; i++){
				input_padded[i] = input[i];
			}
//			input_padded[len_bytes] = (it >> 24) & 0xFF;
//			input_padded[len_bytes+1] = (it >> 16) & 0xFF;
//			input_padded[len_bytes+2] = (it >> 8) & 0xFF;
//			input_padded[len_bytes+3] = (it >> 0) & 0xFF;
			u32_to_u8_little(&input_padded[inputlen_bytes], it);
			sha3_256(input_padded, inputlen_bytes+4, input_pub, input_pub_len_bytes, output1, output_blocklen);
			for(int i=0; i<output_blocklen; i++){
				output[ctr_out++] = output1[i];
			}
		}
	}
}


template <typename T8, typename T64>
void sha3_256_DRBG_xor(
		const T8 input[],
		int inputlen_bytes,
		const uint8_t input_pub[],
		int input_pub_len_bytes,
		T64 output[],
		int output_words){
	assert(inputlen_bytes >=4 );
	int output_blocklen = 256/64;
	assert(output_words % output_blocklen == 0);
	unsigned int sha3_iterations = output_words / output_blocklen;

	int ctr_out = 0;
	for(unsigned int it=0; it<sha3_iterations; it++){
		T64 output1[output_blocklen];
		//append input with bytes i
		T8 input_padded[inputlen_bytes];
		for(int i=0; i<inputlen_bytes; i++){
			input_padded[i] = input[i];
		}

		T8 it_as_u8[4];
		u32_to_u8_little(it_as_u8, it);
//		input_padded[inputlen_bytes-1] ^= ((it >> 0) & 0xFF);
//		input_padded[inputlen_bytes-2] ^= ((it >> 8) & 0xFF);
//		input_padded[inputlen_bytes-3] ^= ((it >> 16) & 0xFF);
//		input_padded[inputlen_bytes-4] ^= ((it >> 24) & 0xFF);
		for(int i=0; i<4; i++){
			input_padded[inputlen_bytes-4+i] ^= it_as_u8[i];
		}
		sha3_256(input_padded, inputlen_bytes, output1, output_blocklen);
		for(int i=0; i<output_blocklen; i++){
			output[ctr_out++] = output1[i];
		}
	}
}

// Required for ZKBoo.
/*
 * Since input to sha function is bounded by 1 cycle, i.e. 32 bytes,
 * the function below is compatible with the whole family of functions: sha3_256, sha3_256_DRBG, and sha3_256_DRBG_xor.
*/
int sha3_256_random_tape_len_in_bytes(int inputlen_bytes, int outputlen_bytes){
	int output_in_64words = (outputlen_bytes * 8) / 64; // SHA3-256
	return 600 * output_in_64words;
}


#endif /* INC_SHA3_H_ */
