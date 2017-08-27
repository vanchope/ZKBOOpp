/*
 * xorshift128plus.h
 *
 *  Created on: Oct 28, 2016
 *      Author: ivan
 */

#ifndef INC_XORSHIFT128PLUS_H_
#define INC_XORSHIFT128PLUS_H_

#include "stdint.h"
#include "assert.h"

// Original version, taken from Vigna, Sebastiano (April 2014). "Further scramblings of Marsaglia's xorshift generators"
//uint64_t xorshift128plus_next(uint64_t s[2]){
//	uint64_t s1 = s[0];
//	const uint64_t s0 = s[1];
//	const uint64_t result = s0 + s1;
//	s[0] = s0;
//	s1 ^= s1 << 23; //a
//	s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5); //b, c
//	return result;
//}


template<typename T64>
T64 xorshift128plus_next(T64 s[2]){
	T64 s1 = s[0];
	const T64 s0 = s[1];
	const T64 result = s0 + s1;
	s[0] = s0;
	s1 ^= s1 << 23; //a
	s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5); //b, c
	return result;
}


template <typename T8, typename T64>
void xorshift128plus(
		const T8 input[] /* input is just 16 bytes = 128 bits */,
		int input_len_bytes /* at most 16 */,
		const uint8_t input_pub[],
		int input_pub_len_bytes,
		T64 output[],
		int output_words /* default is 2*/){
	assert(input_len_bytes <= 16);
	T64 seed[2];
	for(int i=0; i<2; i++)
		seed[i] = 0;
	for(int i=0; i<input_len_bytes && i<8; i++){
		seed[0] |= (T64) (input[i]) << (8 * i);
	}
	for(int i=8; i<input_len_bytes && i<16; i++){
		seed[1] |= (T64) (input[i]) << (8 * (i-8));
	}

	for(int i=0; i<output_words; i++){
		output[i] = xorshift128plus_next(seed);  //seed is updated here
	}
}

// required for ZKBoo
int xorshift128plus_random_tape_len_in_bytes(int inputlen_bytes, int outputlen_bytes){
	// it requires 2 random elements per 128 bits of output
	return  outputlen_bytes + 16; //we add 16 just to fix any rounding errors.
}


#endif /* INC_XORSHIFT128PLUS_H_ */
