/*
 * mpc_types.h
 *
 *  Created on: Aug 31, 2016
 *      Author: ivan
 */

#ifndef INC_MPC_TYPES_H_
#define INC_MPC_TYPES_H_

#include "stdint.h"
#include "stdio.h"
#include <string>

//#define VERBOSE

#define INLINE inline

#define INCLUDE_ASSERTS


#define ZKBOO_NUMBER_OF_ROUNDS    2 // 137 = ZKBoo constant to reduce soundness error to 2^-80 level.

#define ZKBOO_HASH_BYTES	32  // corresponds to 136 rounds

#define ZKBOO_COMMITMENT_VIEW_LENGTH   SHA256_DIGEST_LENGTH   // used only for commitments to views

// _rotr was already defined in global headers, therefore we use our own `implementation' here.
// We avoid templates here just because we want to ensure that only primitive types like uint32_t can be instantiated within the code below.
INLINE uint32_t _rotateright(uint32_t x, int n){
	return (x >> n) | (x << (sizeof(uint32_t)*8-n));
}
INLINE uint32_t _rotateleft(uint32_t x, int n){
	return (x << n) | (x >> (sizeof(uint32_t)*8-n));
}
INLINE uint64_t _rotateright(uint64_t x, int n){
	return (x >> n) | (x << (sizeof(uint64_t)*8-n));
}
INLINE uint64_t _rotateleft(uint64_t x, int n){
	return (x << n) | (x >> (sizeof(uint64_t)*8-n));
}
INLINE uint8_t _rotateright(uint8_t x, int n){
	return (x >> n) | (x << (sizeof(uint8_t)*8-n));
}
INLINE uint8_t _rotateleft(uint8_t x, int n){
	return (x << n) | (x >> (sizeof(uint8_t)*8-n));
}


#define GETBIT(x, i) (((x) >> (i)) & 0x01)
#define SETBIT(x, i, b, T)   x= (b)&1 ? (x)|(((T)1) << (i)) : (x)&(~(((T)1) << (i))) // 64-bit type is supported here

template <typename T8, typename T32>
INLINE T32 u8_to_u32_little(const T8 in[4]){
	T32 res = 0;
	res ^= in[0];
	res = (res << 8) ^ in[1];
	res = (res << 8) ^ in[2];
	res = (res << 8) ^ in[3];
	return res;
}


template <typename T8, typename T32>
INLINE void u32_to_u8_little(T8* out, const T32 &in){
	// b1b2b3b4 -> b4 b3 b2 b1
	out[0] = (T8) (in >> 24);
	out[1] = (T8) (in >> 16);
	out[2] = (T8) (in >>  8);
	out[3] = (T8) (in >>  0);
}

template <typename T32, typename T64>
INLINE T32 u32_to_u64_little(const T32 in[2]){
	T64 res = 0;
	res ^= in[0];
	res = (res << 32) ^ in[1];
	return res;
}


template <typename T32, typename T64>
INLINE void u64_to_u32_little(T32* out, const T64 &in){
	// b1b2b3b4 -> b4 b3 b2 b1
	out[0] = (T32) (in >> 32);
	out[1] = (T32) (in >>  0);
}


// ------------------------------
// Used by trivium and chacha

#define U8TO32_LITTLE(p)		u8_to_u32_little<T8, T32>(p)
#define U32TO8_LITTLE(p, v)		u32_to_u8_little(p, v)

#define U32TO64_LITTLE(p)		u32_to_u64_little<T32, T64>(p)
#define U64TO32_LITTLE(p, v)	u64_to_u32_little(p, v)


// -----------------------------------------------------
// some utilities used by zkboo/zkbpp
// -----------------------------------------------------
void dump_memory(const char * data, int len);

std::string format_memory(const char * data, int len);

template <typename T>
void debug_func(const char * func_name,
		const char * input, int len_bytes,
		const char * inputpub, int inputpub_len_bytes,
		const T * y, int len_output){
	printf("%s('", func_name);
	for(int i=0; i<len_bytes; i++){
		printf("%c", input[i]);
	}
	printf("')=");
	//TODO print also pub params
	const char * out = (const char * ) y;
	unsigned int output_bytes = len_output * sizeof(T);
	dump_memory(out, output_bytes);
	printf("\n");
}

void generate_random(unsigned char data[], int length_bytes);



#endif /* INC_MPC_TYPES_H_ */
