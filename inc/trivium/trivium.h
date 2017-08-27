//
// Taken from http://rijndael.ece.vt.edu/gezel2/bookex/C13_TRIVIUM/trivium_arm_sw/trivium.c on 27.11.2016.
//

//extern unsigned long long getcyclecount();

/* This code is based on the
 *  Reference implementation of the TRIVIUM stream cipher
 *  Christophe De Canniere, K.U.Leuven.
 */

#ifndef INC_TRIVIUM_TRIVIUM_H_
#define INC_TRIVIUM_TRIVIUM_H_

#include "mpc_types.h"
#include "assert.h"

typedef unsigned int  u32;
typedef unsigned char u8;

template <typename T8>
struct ECRYPT_ctx{
	u32 keylen;
	u32 ivlen;
	T8 s[40];
	T8 key[10];
};

/*
typedef struct {
  u32 keylen;
  u32 ivlen;
  u8  s[40];
  u8  key[10];

} ECRYPT_ctx;
*/

//#define U32TO8_LITTLE(p, v) (((u32*)(p))[0] = U32TO32_LITTLE(v)) //FIXME mpc case
//#define U8TO32_LITTLE(p) U32TO32_LITTLE(((u32*)(p))[0]) //FIXME mpc case
//#define U32TO32_LITTLE(v) (v)


#define S00(a, b) ((S(a, 1) << ( 32 - (b))))
#define S32(a, b) ((S(a, 2) << ( 64 - (b))) | (S(a, 1) >> ((b) - 32)))
#define S64(a, b) ((S(a, 3) << ( 96 - (b))) | (S(a, 2) >> ((b) - 64)))
#define S96(a, b) ((S(a, 4) << (128 - (b))) | (S(a, 3) >> ((b) - 96)))

#define UPDATE()                                                             \
  do {                                                                       \
    TT(1) = S64(1,  66) ^ S64(1,  93);                                        \
    TT(2) = S64(2,  69) ^ S64(2,  84);                                        \
    TT(3) = S64(3,  66) ^ S96(3, 111);                                        \
                                                                             \
    Z(TT(1) ^ TT(2) ^ TT(3));                                                   \
                                                                             \
    TT(1) ^= (S64(1,  91) & S64(1,  92)) ^ S64(2,  78);                       \
    TT(2) ^= (S64(2,  82) & S64(2,  83)) ^ S64(3,  87);                       \
    TT(3) ^= (S96(3, 109) & S96(3, 110)) ^ S64(1,  69);                       \
  } while (0)

#define ROTATE()                                                             \
  do {                                                                       \
    S(1, 3) = S(1, 2); S(1, 2) = S(1, 1); S(1, 1) = TT(3);                    \
    S(2, 3) = S(2, 2); S(2, 2) = S(2, 1); S(2, 1) = TT(1);                    \
    S(3, 4) = S(3, 3); S(3, 3) = S(3, 2); S(3, 2) = S(3, 1); S(3, 1) = TT(2); \
  } while (0)

#define LOAD(s)                                                              \
  do {                                                                       \
    S(1, 1) = U8TO32_LITTLE( &(s[0]));                                       \
    S(1, 2) = U8TO32_LITTLE( &(s[4]));                                       \
    S(1, 3) = U8TO32_LITTLE( &(s[8]));                                       \
                                                                             \
    S(2, 1) = U8TO32_LITTLE(&(s[12]));                                       \
    S(2, 2) = U8TO32_LITTLE(&(s[16]));                                       \
    S(2, 3) = U8TO32_LITTLE(&(s[20]));                                       \
                                                                             \
    S(3, 1) = U8TO32_LITTLE(&(s[24]));                                       \
    S(3, 2) = U8TO32_LITTLE(&(s[28]));                                       \
    S(3, 3) = U8TO32_LITTLE(&(s[32]));                                       \
    S(3, 4) = U8TO32_LITTLE(&(s[36]));                                       \
  } while (0)

#define STORE(s)                                                            \
  do {                                                                      \
    U32TO8_LITTLE( &(s[0]), S(1, 1));                                       \
    U32TO8_LITTLE( &(s[4]), S(1, 2));                                       \
    U32TO8_LITTLE( &(s[8]), S(1, 3));                                       \
                                                                            \
    U32TO8_LITTLE(&(s[12]), S(2, 1));                                       \
    U32TO8_LITTLE(&(s[16]), S(2, 2));                                       \
    U32TO8_LITTLE(&(s[20]), S(2, 3));                                       \
                                                                            \
    U32TO8_LITTLE(&(s[24]), S(3, 1));                                       \
    U32TO8_LITTLE(&(s[28]), S(3, 2));                                       \
    U32TO8_LITTLE(&(s[32]), S(3, 3));                                       \
    U32TO8_LITTLE(&(s[36]), S(3, 4));                                       \
  } while (0)

template <typename T8>
void ECRYPT_keysetup(
  ECRYPT_ctx<T8>* ctx,
  const T8* key,
  u32 keysize_bits /*max 80*/,
  u32 ivsize_bits)
{
	u32 i;

	ctx->keylen = (keysize_bits + 7) / 8;
	ctx->ivlen = (ivsize_bits + 7) / 8;

	for (i = 0; i < ctx->keylen; ++i)
		ctx->key[i] = key[i];
	for (i=ctx->keylen; i<10; ++i)
		ctx->key[i] = 0;
}

#define S(a, n) (s##a##n)
#define TT(a) (t##a)     // T(a) changed to TT(a) to avoid comflict with template type T followed by (

template <typename T8, typename T32>
void ECRYPT_ivsetup(
  ECRYPT_ctx<T8>* ctx,
  const u8* iv)
{
  u32 i;

  T32 s11, s12, s13;
  T32 s21, s22, s23;
  T32 s31, s32, s33, s34;

  //s[0] till s[11] -- corresponds to key
  for (i = 0; i < ctx->keylen; ++i)
    ctx->s[i] = ctx->key[i];
  for (i = ctx->keylen; i < 12; ++i)
    ctx->s[i] = 0;

  //s[12] till s[23] -- corresponds to IV
  for (i = 0; i < ctx->ivlen; ++i)
    ctx->s[i + 12] = iv[i];
  for (i = ctx->ivlen; i < 12; ++i)
    ctx->s[i + 12] = 0;

  //s[24] till s[36] -- zeros
  for (i = 0; i < 13; ++i)
    ctx->s[i + 24] = 0;

  // s[37]
  ctx->s[13 + 24] = 0x70;

  //FIXME added!
  ctx->s[38] = 0;
  ctx->s[39] = 0;

  LOAD(ctx->s);

#define Z(w)

  for (i = 0; i < 4 * 9; ++i)
    {
      T32 t1, t2, t3;
      
      UPDATE();
      ROTATE();
    }

  STORE(ctx->s);
}

template <typename T8, typename T32>
void ECRYPT_process_bytes(
  int action,
  ECRYPT_ctx<T8>* ctx,
  const T8* input, // just because we use zeros input for PRG, we stay with u8 and not with T8
  T32* output32, // to simplify mpc case, we change u8 to u32
  u32 msglen_bytes)
{

  u32 i;

  T32 s11, s12, s13;
  T32 s21, s22, s23;
  T32 s31, s32, s33, s34;

  //u32 z;

  LOAD(ctx->s);

#undef Z
//#define Z(w) (U32TO8_LITTLE(output + 4 * i, U8TO32_LITTLE(input + 4 * i) ^ w))
#define Z(w) (output32[i] = U8TO32_LITTLE(input + 4 * i) ^ w)

  for (i = 0; i < msglen_bytes / 4; ++i)
    {
      T32 t1, t2, t3;
      
      UPDATE();
      ROTATE();
    }

#undef Z
#define Z(w) (z = w)

  STORE(ctx->s);
}

/* ------------------------------------------------------------------------- */

template <typename T8, typename T32>
void trivium(
		const T8 input[],
		int input_len_bytes /*must be 10*/, // it is a seed for PRG
		const uint8_t input_pub[],
		int input_pub_len_bytes,
		T32 output[],
		int output_words /* default is ??*/)
{
	assert(input_len_bytes <= 10);
	ECRYPT_ctx<T8> trivium_state;

	u8 iv[10];
	for(int i=0; i<10; i++){
		iv[i] = 0;
	};

	u32 msg_len_bytes = output_words * sizeof(u32);
	//T8 input_zero[msg_len_bytes];
	T8* input_zero = new T8[msg_len_bytes];
	for(unsigned int i=0; i<msg_len_bytes; i++){
		input_zero[i] = 0;
	}

	ECRYPT_keysetup(&trivium_state, input, input_len_bytes*8, 10*8);
	ECRYPT_ivsetup<T8, T32>(&trivium_state, iv);

	ECRYPT_process_bytes(0, &trivium_state, input_zero, output, msg_len_bytes);
	delete[] input_zero;
}


// required for ZKBoo
int trivium_random_tape_len_in_bytes(int inputlen_bytes, int outputlen_bytes){
	return  (3 * outputlen_bytes / 4 + 108) * 4 + 16;
}

#endif /* INC_TRIVIUM_TRIVIUM_H_ */
