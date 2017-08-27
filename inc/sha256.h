/*
 * The reference implementation of SHA-256 algorithm based on pseudocode from Wikipedia,
 * with two improvements in computing variables 'ch' and 'maj' taken from ZKBoo reference implementation.
 *
 * Expected output:
 *
 * SHA256('')=E3B0C442 98FC1C14 9AFBF4C8 996FB924 27AE41E4 649B934C A495991B 7852B855
 *
 *  Created on: Aug 22, 2016
 *      Author: ivan
 *
 */

#ifndef INC_SHA256_H_
#define INC_SHA256_H_

#include "stdio.h"
#include "assert.h"
#include "string.h"
#include <iostream>

#include "MpcVariable.h"

const uint32_t mask512=0x01FF;

template <typename T>
std::ostream& operator<< (std::ostream& os, MpcVariableVerify<T> const& v){
	return os << "varVer[ " << v.val[0] << " ; " << 	v.val[1] << "]";
}


//uint32_t check_endian(uint32_t x){
//	return __builtin_bswap32(x);
//}

//
// Based on pseudocode SHA-256 from https://en.wikipedia.org/wiki/SHA-2
// Input divides 512 bits / 64 bytes / 16 words
// Output is 32 bytes = 8 words = 256 bits
//
// FIXME our implementation uses 900 AND and ADD operations, but theirs 600+192 = 792. (update info)
template <typename T8, typename R> // R is either uint32_t or MpcVariable<uint32_t>.
void sha256(const T8 * input, int input_len_bytes,
		const uint8_t input_pub[],
		int input_pub_len_bytes,
		R *res /* is always 8 words, i.e. 32 bytes */, int output_words){
	assert(output_words == 8);

	// Preprocessing.
	// Input len is unbounded, but we limit it to simplify our life.
	int MAX_LEN = 1000 * 1000 * 1000;
	assert (input_len_bytes < MAX_LEN);

	// Pre-processing
	int len2bytes = input_len_bytes + 1;
	int appendBits = (512 + 448 - ((len2bytes << 3) & 511)) & 511;
	assert ((appendBits & 7) == 0);
	int lenFinalBytes = len2bytes + (appendBits >> 3) + 8; // last 64 bits for encoding "len"

	// output len always divides 512 bit
	T8 preprocessed_input[lenFinalBytes]; // preprocessed input bytes

	for (int i=0; i<input_len_bytes; i++){
		preprocessed_input[i] = input[i];
	}
	preprocessed_input[input_len_bytes] = 0x80;
	for(int i=input_len_bytes+1; i<lenFinalBytes; i++){
		preprocessed_input[i] = 0;
	}

	// Reverse the order of bytes in 4-byte words.
//	uint32_t * inputBytes_as_uint32 = (uint32_t*) x;
//	for(size_t i=0; i<lenFinalBytes / sizeof(uint32_t); i++){
//		inputBytes_as_uint32[i] = check_endian(inputBytes_as_uint32[i]);
//	}

	// Store the length at the end of the buffer.
	//int* ptrLen = (int*) (&preprocessed_input[lenFinalBytes-4]);
	//*ptrLen = (input_len_bytes * 8); // len in bits before preprocessing
	preprocessed_input[lenFinalBytes - 4] = (input_len_bytes * 8 >> 24) & 0xFF;
	preprocessed_input[lenFinalBytes - 3] = (input_len_bytes * 8 >> 16) & 0xFF;
	preprocessed_input[lenFinalBytes - 2] = (input_len_bytes * 8 >> 8) & 0xFF;
	preprocessed_input[lenFinalBytes - 1] = (input_len_bytes * 8 >> 0) & 0xFF;



	// Note 2: For each round, there is one round constant k[i] and one entry in the message schedule array w[i], 0 ≤ i ≤ 63
	// Note 4: Big-endian convention is used when expressing the constants in this pseudocode,
    // and when parsing message block data from bytes to words, for example,
    // the first word of the input message "abc" after padding is 0x61626380

	// Initialize hash values
	uint32_t hh_uint32[8] = {
		0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
	};

	R hh[8];
	for(int i=0; i<8; i++)
		hh[i] = hh_uint32[i];

	// Initialize array of round constants
	const uint32_t k[64] = {
	   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	// Process the message in successive 512-bit chunks; it is the input to SHA
	// T represents a word, i.e. 32 bits = 4 bytes
	int input_len_words = lenFinalBytes >> 2;
	for(int offsetChunk=0; offsetChunk<input_len_words; offsetChunk+=(512/32)){
		R w[64];
		for(int i=0; i<64; i++){
			w[i] = 0;
		}
		int j=0;
		for(int i=0; i<16; i++){
			for(int b=0; b<32/8; b++,j++){
				w[i] |= (R) preprocessed_input[j] << (24 - 8 * b);
			}
		}
		for(int i=16; i<64; i++){
			R s0 = _rotateright(w[i-15], 7) ^ (_rotateright(w[i-15], 18)) ^ (w[i-15] >> 3);
			R s1 = _rotateright(w[i-2], 17) ^ (_rotateright(w[i-2], 19)) ^ (w[i-2] >> 10);
			w[i] = w[i-16] + s0 + w[i-7] + s1;
		}

		R a = hh[0];
		R b = hh[1];
		R c = hh[2];
		R d = hh[3];
		R e = hh[4];
		R f = hh[5];
		R g = hh[6];
		R h = hh[7];

		// Compression function main loop
		for(int i=0; i<64; i++){
			R S1 = _rotateright(e, 6) ^ _rotateright(e, 11) ^ _rotateright(e, 25);
			//R ch = (e & f) ^ ((~e) & g);
			R ch = (e & (f^g)) ^ g; //Optimization for 'ch' to save one operation
			R temp1 = h + S1 + ch + k[i] + w[i];
			R S0 = _rotateright(a, 2) ^ _rotateright(a, 13) ^ _rotateright(a, 22);
			//R maj = (a & b) ^ (a & c) ^ (b & c);
			R maj = ((a^b) & (a^c)) ^ a; //Optimization for 'maj' to save one operation
			R temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;
		}

		// Add the compressed chunk to the current hash value
		hh[0] += a;
		hh[1] += b;
		hh[2] += c;
		hh[3] += d;
		hh[4] += e;
		hh[5] += f;
		hh[6] += g;
		hh[7] += h;
	}

	for(int i=0; i<8; i++){
		res[i] = hh[i];
	}
}

int sha256_random_tape_len_in_bytes(int inputlen_bytes, int outputlen_bytes){
	// #random operations per one chunk of 512 bytes X #chunks
	return  (728 * 32) * ((inputlen_bytes+511) / 512);
}

#endif /* INC_SHA256_H_ */
