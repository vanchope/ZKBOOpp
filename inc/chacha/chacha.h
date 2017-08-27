/*
 * Chacha stream cipher.
 * Taken from https://cr.yp.to/chacha.html on Nov 28, 2016.
 *
 *
 * chacha-ref.c version 20080118
 * D. J. Bernstein
 * Public domain.
*/


// Instead of including a portable code, we define locally everything we need.
//#include "ecrypt-sync.h"
#include "mpc_types.h"

#define u8 uint8_t
#define u32 uint32_t

//#define ROTATE(v,c) (ROTL32(v,c))
#define ROTATE(v,c) (_rotateleft(v,c))
#define XOR(v,w) ((v) ^ (w))
//#define PLUS(v,w) (U32V((v) + (w)))
#define PLUS(v,w) ((v) + (w))
#define PLUSONE(v) (PLUS((v),1))

template <typename T32>
struct ECRYPT_ctx
{
  T32 input[16];
};



#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);

template <typename T32>
static void salsa20_wordtobyte(T32 output[16], const T32 input[16]) {
	T32 x[16];
	int i;

	for (i = 0; i < 16; ++i)
		x[i] = input[i];
	for (i = 8; i > 0; i -= 2) {
		QUARTERROUND(0, 4, 8, 12)
		QUARTERROUND(1, 5, 9, 13)
		QUARTERROUND(2, 6, 10, 14)
		QUARTERROUND(3, 7, 11, 15)
		QUARTERROUND(0, 5, 10, 15)
		QUARTERROUND(1, 6, 11, 12)
		QUARTERROUND(2, 7, 8, 13)
		QUARTERROUND(3, 4, 9, 14)
	}
	for (i = 0; i < 16; ++i)
		x[i] = PLUS(x[i], input[i]);
	for (i = 0; i < 16; ++i)
		//U32TO8_LITTLE(output + 4 * i, x[i]);
		output[i] = x[i];
}

void ECRYPT_init(void) {
	return;
}

static const char sigma[17] = "expand 32-byte k";
static const char tau[17]   = "expand 16-byte k";

template <typename T8, typename T32>
void ECRYPT_keysetup(ECRYPT_ctx<T32> *x, const T8 *k /* 32 or 16 bytes*/, u32 kbits) {
	const char *constants;

	x->input[4] = U8TO32_LITTLE(k + 0);
	x->input[5] = U8TO32_LITTLE(k + 4);
	x->input[6] = U8TO32_LITTLE(k + 8);
	x->input[7] = U8TO32_LITTLE(k + 12);
	if (kbits == 256) { /* recommended */
		k += 16;
		constants = sigma;
	} else { /* kbits == 128 */
		constants = tau;
	}
	x->input[8] = U8TO32_LITTLE(k + 0);
	x->input[9] = U8TO32_LITTLE(k + 4);
	x->input[10] = U8TO32_LITTLE(k + 8);
	x->input[11] = U8TO32_LITTLE(k + 12);
	T8 constants_u8[16];
	for(int i=0; i<16; i++){
		constants_u8[i] = constants[i];
	}
	x->input[0] = U8TO32_LITTLE(constants_u8 + 0);
	x->input[1] = U8TO32_LITTLE(constants_u8 + 4);
	x->input[2] = U8TO32_LITTLE(constants_u8 + 8);
	x->input[3] = U8TO32_LITTLE(constants_u8 + 12);
}

template <typename T32>
void ECRYPT_ivsetup(ECRYPT_ctx<T32> *x, const T32 *iv /* [8 bytes] = [4*2] */) {
	x->input[12] = 0;
	x->input[13] = 0;
	x->input[14] = iv[0];//U8TO32_LITTLE(iv + 0);
	x->input[15] = iv[1];//U8TO32_LITTLE(iv + 4);
}

template <typename T32, typename T64>
void ECRYPT_encrypt_bytes(ECRYPT_ctx<T32> *x, const T32 *m, T32 *c, u32 words) {
	T32 output[16];
	unsigned int i;

	if (!words)
		return;
	for (;;) {
		//FIXME mpc setting!
		salsa20_wordtobyte(output, x->input);

		T64 number = U32TO64_LITTLE(&(x->input[12]));
		number = PLUSONE(number);
		//U32TO8_LITTLE(output + 4 * i, x[i]);
		U64TO32_LITTLE(&(x->input[12]), number);

//		x->input[12] = PLUSONE(x->input[12]);
//		if (!x->input[12]) {
//			x->input[13] = PLUSONE(x->input[13]);
//			/* stopping at 2^70 bytes per nonce is user's responsibility */
//		}


		if (words <= 16) {
			for (i = 0; i < words; ++i)
				c[i] = m[i] ^ output[i];
			return;
		}
		for (i = 0; i < 16; ++i)
			c[i] = m[i] ^ output[i];
		words -= 16;
		c += 16;
		m += 16;
	}
}

template <typename T32, typename T64>
void ECRYPT_decrypt_bytes(ECRYPT_ctx<T32> *x, const T32 *c, T32 *m, u32 words) {
	ECRYPT_encrypt_bytes<T32, T64>(x, c, m, words);
}

//template <typename T32>
//void ECRYPT_keystream_bytes(ECRYPT_ctx<T32> *x, u8 *stream, u32 bytes) {
//	u32 i;
//	for (i = 0; i < bytes; ++i)
//		stream[i] = 0;
//	ECRYPT_encrypt_bytes(x, stream, stream, bytes);
//}

//-----------------------------------------------------------------
// PRG based on chacha

template <typename T8, typename T32, typename T64>
void chacha(
		const T8 input[],
		int input_len_bytes /*in chacha it must be 32(better) or 16*/, // it is a seed for PRG
		const uint8_t input_pub[],
		int input_pub_len_bytes,
		T32 output[],
		int output_words /* default is ??*/){

	assert(input_len_bytes==16 || input_len_bytes==32);

	ECRYPT_ctx<T32> ctx;
	ECRYPT_keysetup(&ctx, input, input_len_bytes * 8);
	T32 iv[2];
	iv[0] = 0;
	iv[1] = 0;
	ECRYPT_ivsetup(&ctx, iv);
	T32 m[output_words];
	for(int i=0; i<output_words; i++){
		m[i] = 0;
	}
	ECRYPT_encrypt_bytes<T32, T64>(&ctx, m, output, output_words);
}


// required for ZKBoo
int chacha_random_tape_len_in_bytes(int inputlen_bytes, int outputlen_bytes){
	return 4 * (128+16) * (64 + outputlen_bytes) / 64 + 16;
}

