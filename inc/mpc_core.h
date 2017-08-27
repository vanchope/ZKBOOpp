/*
 * MpcCore.h
 *
 *  Created on: Oct 7, 2016
 *      Author: ivan
 */

#ifndef INC_MPC_CORE_H_
#define INC_MPC_CORE_H_

#include "MpcVariable.h"
#include <openssl/sha.h>
#include <algorithm>
#include <sstream>
#include "assert.h"
#include "Matrix.h"


void dump_memory(const char * data, int len);

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



//  String format of the proof-commitment:
//
//  [4:input_size_bytes]  [4:output_size_bytes]   # header
//  [output_size_bytes * NUMBER_OF_ROUNDS * 3]  # yp
//  [NUMBER_OF_ROUNDS * 3 * SHA256_DIGEST_LEN]  # hash
//
template <typename T>   // output type, e.g. uint32_t
std::string convert_proof_commitment_to_string(int input_bytes, int output_len_bytes,
		//const T yp[][ZKBOO_NUMBER_OF_ROUNDS][3] /*IN*/ /*first dimention is output_in_words*/,
		const T yp[], // it is a contiguous memory region
		unsigned char hash[ZKBOO_NUMBER_OF_ROUNDS][3][SHA256_DIGEST_LENGTH]){
	std::vector<std::string> vector_res;
	// 1. Header =  8-bytes string for input and output sizes in bytes
	uint8_t header[sizeof(uint32_t) * 2];
	uint32_t* inputsize_ptr = (uint32_t*)(header);
	*inputsize_ptr = input_bytes;
	uint32_t* outputsize_ptr = (uint32_t*)(header + sizeof(uint32_t));
	*outputsize_ptr = output_len_bytes;
	std::string header_str((char *) header, sizeof(header));
	vector_res.push_back(header_str); // [0]

	// 2. yp
	std::string yp_str((char *) yp, output_len_bytes * ZKBOO_NUMBER_OF_ROUNDS * 3);
	vector_res.push_back(yp_str); // [1]

	// 3. hash
	std::string hash_str((char *) hash, ZKBOO_NUMBER_OF_ROUNDS * 3 * SHA256_DIGEST_LENGTH);
	vector_res.push_back(hash_str); // [2]

	std::string res = vectorstrings_to_string(vector_res);
	return res;
}

//  String format of the proof-response:
//
//  [NUMBER_OF_ROUNDS * 2 of MpcPartyView]      # MpcPartyView[]
std::string convert_proof_response_to_string(const MpcProof z[]);


template <typename T>   // output type, e.g. uint32_t
void convert_string_to_proof(
			const std::vector<std::string> &proof_commit,
			const std::vector<std::string> &proof_vs,
			int output_words,
		const mpc::Matrix3D<T> &yp /*OUT*/, // equiv. of [][ZKBOO_NUMBER_OF_ROUNDS][3], where first dimension is output_in_words extracted from the proof
		unsigned char hash[ZKBOO_NUMBER_OF_ROUNDS][3][SHA256_DIGEST_LENGTH] /*OUT*/,
		MpcProof z[] /*OUT*/){

	const char * data = proof_commit[1].data();
	assert(proof_commit[1].size() == sizeof(T) * output_words * ZKBOO_NUMBER_OF_ROUNDS * 3);

	memcpy(&yp.data[0], data, sizeof(T) * output_words * ZKBOO_NUMBER_OF_ROUNDS * 3); // memory is contiguous, so we can write that
	memcpy(hash, proof_commit[2].data(), proof_commit[2].size());

	unsigned int index = 0;
	for(int i=0; i<ZKBOO_NUMBER_OF_ROUNDS; i++){
		for(int j=0; j<2; j++){
			assert(index < proof_vs.size());
			z[i].pView[j] = string_to_MpcPartyView(proof_vs[index++]);
		}
	}
}


template <typename T>   // output type, e.g. uint32_t
std::string zkboo_prove_commit(
			std::vector<std::string> &zkboo_proof_3parts /*OUT*/ /*for each x_1,x_2,x_3*/,
		const char * function_name,
		const char * input, int input_bytes,
		const char * inputpub, int inputpub_len_bytes,
		const char * output, int output_len_bytes,
		int random_tape_len_in_bytes,
		void (*func)(const MpcVariable<uint8_t>* input, int input_len_bytes,
				const uint8_t inputpub[], int inputpub_len_bytes,
				MpcVariable<T>* z, int output_in_words)){
	assert ((output_len_bytes & (sizeof(T) - 1)) == 0 && output_len_bytes > 0);
	int output_in_words = output_len_bytes / sizeof(T);

	// output per each party
	mpc::Matrix3D<T> yp(output_in_words, ZKBOO_NUMBER_OF_ROUNDS, 3); // default initialize to 0

	unsigned char hashView[ZKBOO_NUMBER_OF_ROUNDS][3][SHA256_DIGEST_LENGTH]; // commitment to each virtual mpc party computation

	for(int iRound=0; iRound<ZKBOO_NUMBER_OF_ROUNDS; iRound++){
		MpcPartyContext ctxArray[3];
		MpcPartyContext* ctx[3];

		MpcVariable<uint8_t> input_mpc[input_bytes];
		for(int ip=0; ip<3; ip++) {// ip = iParty
			ctx[ip] = &ctxArray[ip];
			InitMpcContext(ctx[ip], random_tape_len_in_bytes, false);
		}
		for(int ilen=0; ilen<input_bytes; ilen++){
			convert_input(input_mpc[ilen], input[ilen], (const MpcPartyContext**)ctx); // input is split into 3 random parts
			for(int ip=0; ip<3; ip++){
				ctx[ip]->view.input.push_back(input_mpc[ilen].value(ip));
			}
		}
		MpcVariable<T>* res = new MpcVariable<T>[output_in_words];

		(*func)(input_mpc, input_bytes, (uint8_t*)inputpub, inputpub_len_bytes, res, output_in_words); // +-+-+-+-+

		//add res[] to output before committing MpcContext
		for(int ip=0; ip<3; ip++){
			for(int iw=0; iw<output_in_words; iw++){
				//yp[iw][iRound][ip] = res[iw].value(ip);
				yp.data[yp.index(iw,iRound,ip)] = res[iw].value(ip);
				if (sizeof(T)==4){
					ctx[ip]->view.output32.push_back(res[iw].value(ip));
				}else if (sizeof(T)==8){
					ctx[ip]->view.output64.push_back(res[iw].value(ip));
				}else{
					throw std::runtime_error("not supported");
				}
			}
		}
		//commit keys and view
		for(int ip=0; ip<3; ip++){
			CommitMpcContext((unsigned char*) &hashView[iRound][ip], ctx[ip]);
		}
		if (iRound == 0){
			printf("used randomness elements: %d\n",  ctx[0]->randomnessUsed);
		}

		// store all views into vector z
		for(int iParty=0; iParty<3; iParty++){
			std::string view_str = MpcPartyView_to_string(ctx[iParty]->view);
			zkboo_proof_3parts.push_back(view_str);
		}

		delete[] res;
	}

	T* y = new T[output_in_words];
	for(int i=0; i<output_in_words; i++){
		//y[i] = yp[i][0][0] ^ yp[i][0][1] ^ yp[i][0][2];
		y[i] = yp.data[yp.index(i,0,0)] ^ yp.data[yp.index(i,0,1)] ^ yp.data[yp.index(i,0,2)];
	}
	if (memcmp(output, y, output_len_bytes)!=0){
		dump_memory(output, output_len_bytes);
		printf("\n");
		dump_memory((char *) y, output_len_bytes);
		printf("\n");
		throw std::runtime_error("expected output and final output during the proof are not equal! (dump follows)");
	}
	//debug_func(function_name, input, input_bytes, (char*)inputpub, inputpub_len_bytes, y, output_in_words);

	std::string proof_com = convert_proof_commitment_to_string(input_bytes, output_len_bytes, yp.data, hashView);
	delete[] y;
	return proof_com;
}

std::vector<std::string> zkboo_prove_response(const std::vector<std::string> &z_all, const unsigned char hash[ZKBOO_HASH_BYTES]);




//returns proof commit
template <typename T>   // output type, e.g. uint32_t
std::string zkboo_fake_prove(
			std::vector<std::string> &zkboo_proof_2parts /*OUT*/ /*for 2 out of 3 in {x_1,x_2,x_3}*/,
		const char * function_name,
		const unsigned char hash[ZKBOO_HASH_BYTES], int input_bytes,
		const char * inputpub, int inputpub_len_bytes,
		const char * output, int output_len_bytes,
		int random_tape_len_in_bytes,
		void (*func)(const MpcVariableVerify<uint8_t>* input, int input_len_bytes,
				const uint8_t inputpub[], int inputpub_len_bytes,
				MpcVariableVerify<T>* z, int output_in_words)){
	assert ((output_len_bytes & (sizeof(T) - 1)) == 0 && output_len_bytes > 0);
	int output_in_words = output_len_bytes / sizeof(T);

	T* y = (T*) output;
	mpc::Matrix3D<T> yp(output_in_words, ZKBOO_NUMBER_OF_ROUNDS, 3); // output per each party
	unsigned char hashView[ZKBOO_NUMBER_OF_ROUNDS][3][SHA256_DIGEST_LENGTH]; // commitment to each virtual mpc party computation

	//FIXME T instead of uint32_t?
	mpc::Matrix2D<uint32_t> fake_randomness(ZKBOO_NUMBER_OF_ROUNDS, 1 + (random_tape_len_in_bytes / sizeof(uint32_t)));
	generate_random((unsigned char*) fake_randomness.data, fake_randomness.size_bytes());


	MpcPartyContext ctxArray[ZKBOO_NUMBER_OF_ROUNDS][2];
	MpcPartyContext* ctx[ZKBOO_NUMBER_OF_ROUNDS][2];

	int es[ZKBOO_NUMBER_OF_ROUNDS];
	extract_es_from_Challenge(es, hash);
	for (int iRound = 0; iRound < ZKBOO_NUMBER_OF_ROUNDS; ++iRound) {
		MpcVariableVerify<uint8_t> input_mpc[input_bytes];
		for(int ip=0; ip<2; ip++) {
			ctx[iRound][ip] = &ctxArray[iRound][ip];
			InitMpcContext(ctx[iRound][ip], random_tape_len_in_bytes, false);
		}
		for(int ilen=0; ilen<input_bytes; ilen++){
			uint8_t shares[2];
			generate_random((unsigned char *)shares, 2*sizeof(uint8_t));
			fake_randomness.data[fake_randomness.index(iRound, 0)] = 1;  // set the first element to 1, it is a counter
			input_mpc[ilen] = MpcVariableVerify<uint8_t>(shares, (const MpcPartyContext**)ctx[iRound],
					&fake_randomness.data[fake_randomness.index(iRound, 0)]);
			for(int ip=0; ip<2; ip++){
				ctx[iRound][ip]->view.input.push_back(input_mpc[ilen].value(ip));
			}
		}

		MpcVariableVerify<T>* res = new MpcVariableVerify<T>[output_in_words];
		(*func)(input_mpc, input_bytes, (uint8_t*)inputpub, inputpub_len_bytes, res, output_in_words); // +-+-+-+-+

		//add res[] to output before committing MpcContext
		for(int iw=0; iw<output_in_words; iw++){
			for(int ip=0; ip<2; ip++){
				//yp[iw][iRound][(es[iRound] + ip) % 3] =
				yp.data[yp.index(iw,iRound,(es[iRound] + ip) % 3)] = res[iw].value(ip);
				if (sizeof(T)==4){
					ctx[iRound][ip]->view.output32.push_back(res[iw].value(ip));
				}else if (sizeof(T)==8){
					ctx[iRound][ip]->view.output64.push_back(res[iw].value(ip));
				}else{
					throw std::runtime_error("not supported");
				}
			}
			//yp[iw][iRound][(es[iRound] + 2) % 3] =
			yp.data[yp.index(iw,iRound,(es[iRound] + 2) % 3)] = y[iw] ^ res[iw].value(0) ^ res[iw].value(1);
		}
		//commit keys and view
		for(int ip=0; ip<2; ip++){
			CommitMpcContext((unsigned char*) &hashView[iRound][(es[iRound] + ip) % 3], ctx[iRound][ip]);

			/*
			printf("C++ | Committing in fake proof ZKBoo: ");
			dump_memory((const char *)(unsigned char*) &hashView[iRound][(es[iRound] + ip) % 3], SHA256_DIGEST_LENGTH);
			printf(" with randomness: ");
			dump_memory((const char *) &ctx[iRound][ip]->view.rnd_tape_seed, 16);
			printf("\n");
			*/
		}
		generate_random((unsigned char*) &hashView[iRound][(es[iRound] + 2) % 3], SHA256_DIGEST_LENGTH);
		delete[] res;
	}
	printf("used randomness elements: %d\n",  ctx[0][0]->randomnessUsed);

	// store all views into vector z
	for(int iRound=0; iRound<ZKBOO_NUMBER_OF_ROUNDS; iRound++){
		for(int iParty=0; iParty<2; iParty++){
			std::string view_str = MpcPartyView_to_string(ctx[iRound][iParty]->view);
			zkboo_proof_2parts.push_back(view_str);
		}
	}

	std::string proof_com = convert_proof_commitment_to_string(input_bytes, output_len_bytes, yp.data, hashView);
	return proof_com;
}


template <typename T>   // output type, e.g. uint32_t
bool zkboo_verify(const char * function_name,
		const unsigned char hash_v[ZKBOO_HASH_BYTES],
		const char * inputpub, int inputpub_len_bytes,
		const char * output, int output_len_bytes,
		int random_tape_len_in_bytes,
		void (*func_verif)(const MpcVariableVerify<uint8_t>* input, int input_len_bytes,
				const uint8_t inputpub[], int inputpub_len_bytes,
				MpcVariableVerify<T>* z, int output_in_words),
		const std::string& proof_commit /*IN*/,
		const std::vector<std::string> &z_str /*IN*/){

	std::vector<std::string> proof_commit_vs = string_to_vectorstrings(proof_commit);
	std::string header_str = proof_commit_vs[0];
	//uint32_t* inputsize_ptr = (uint32_t*) header_str.data();
	uint32_t* outputsize_ptr = (uint32_t*) header_str.data() + 1; //next 4 bytes

	int output_in_words = *outputsize_ptr / sizeof(T);
	mpc::Matrix3D<T> yp(output_in_words, ZKBOO_NUMBER_OF_ROUNDS, 3);
	unsigned char hashViews[ZKBOO_NUMBER_OF_ROUNDS][3][SHA256_DIGEST_LENGTH];
	MpcProof zp[ZKBOO_NUMBER_OF_ROUNDS];
	convert_string_to_proof(proof_commit_vs, z_str, output_in_words, yp, hashViews, zp);

	T* expected_output = (T*) output;
	for(int offset=0; offset<output_in_words; offset++){
		for(int i=0; i<ZKBOO_NUMBER_OF_ROUNDS; i++){
			long int off3d = yp.index(offset, i, 0);
			T y_received = yp.data[off3d] ^ yp.data[off3d+1] ^ yp.data[off3d+2]; //equiv. to yp[offset][i][0] ^ yp[offset][i][1] ^ yp[offset][i][2];
			if (y_received != *(expected_output+offset)){
				//printf("C++ | expected output does not match the received. verify returns false\n"); //FIXME connect with view32/64
				return false;
			}
		}
	}

	int es[ZKBOO_NUMBER_OF_ROUNDS];
	extract_es_from_Challenge(es, hash_v);

	T* y = new T[output_in_words];
	for(int i=0; i<output_in_words; i++){
		long int off3d = yp.index(i, 0, 0);
		y[i] = yp.data[off3d] ^ yp.data[off3d+1] ^ yp.data[off3d+2]; //equiv. y[i] = yp[i][0][0] ^ yp[i][0][1] ^ yp[i][0][2];
	}

	MpcPartyContext ctxArray[ZKBOO_NUMBER_OF_ROUNDS][2];
	MpcPartyContext* ctx[ZKBOO_NUMBER_OF_ROUNDS][2];
	int input_words = zp[0].pView[0].input.size();
	assert (input_words >= 0);
	bool verification_ok = true;
	try{
		for(int iRound=0; iRound < ZKBOO_NUMBER_OF_ROUNDS; iRound++){
			for(int i=0; i<2; i++){
				ctx[iRound][i] = &ctxArray[iRound][i];
				//prepare context
				InitMpcContext(ctx[iRound][i], zp[iRound].pView[i].rnd_tape_seed, random_tape_len_in_bytes, true);
				ctx[iRound][i]->view = zp[iRound].pView[i];
				ctx[iRound][i]->verifier_counter32 = 0;
				ctx[iRound][i]->verifier_counter64 = 0;
			}
			// prepare MpcVariableVerify
			MpcVariableVerify<uint8_t> input_v[input_words];
			MpcVariableVerify<T>* res_v = new MpcVariableVerify<T>[output_in_words];

			for(int iw=0; iw<input_words; iw++){
				uint8_t xp[2];
				for(int i=0; i<2; i++){
					xp[i] = ctx[iRound][i]->view.input[iw];
				}
				input_v[iw] = MpcVariableVerify<uint8_t>(xp, (const MpcPartyContext**)ctx[iRound]);
			}

			(*func_verif)(input_v, input_words, (uint8_t*)inputpub, inputpub_len_bytes, res_v, output_in_words); // +-+-+-+-+
			// the fact that the function did not throw any exception at this point means that
			// the output part of ctx[0].view was correctly verified

			//cmp local output with the views provided by the prover
			for(int ip=0; ip<2; ip++){
				for(int iw=0; iw<output_in_words; iw++){
					if (sizeof(T)==4){
						assert (ctx[iRound][ip]->view.output32[ctx[iRound][ip]->verifier_counter32] == res_v[iw].value(ip));
						ctx[iRound][ip]->verifier_counter32++;
					}else if (sizeof(T)==8){
						assert (ctx[iRound][ip]->view.output64[ctx[iRound][ip]->verifier_counter64] == res_v[iw].value(ip));
						ctx[iRound][ip]->verifier_counter64++;
					}else {
						throw std::runtime_error("not supported");
					}
					//FIXME check? or just H
				}
			}

			//verify that MpcContext hash commitment was computed correctly and matches the challenge value
			unsigned char hash_ctx_v[SHA256_DIGEST_LENGTH];
			assert (ctx[iRound][0]->view.output32.size() == ctx[iRound][0]->verifier_counter32);
			assert (ctx[iRound][0]->view.output64.size() == ctx[iRound][0]->verifier_counter64);
			CommitMpcContext(hash_ctx_v, ctx[iRound][0]);

			/*
			printf("C++ | Committing in verify proof ZKBoo: ");
				dump_memory((const char *) hash_ctx_v, SHA256_DIGEST_LENGTH);
				printf(" with randomness: ");
				dump_memory((const char *) ctx[iRound][0]->view.rnd_tape_seed, 16);
			printf("\n");
			*/

			/*
			printf("C++ | Hashes in ZKBoo do not match! Expected ");
				dump_memory((const char *)&(hashViews[iRound][es[iRound]][0]), SHA256_DIGEST_LENGTH);
				printf(", but received ");
				dump_memory((const char *)hash_ctx_v, SHA256_DIGEST_LENGTH);
			printf("\n");
			*/

			if (memcmp(&(hashViews[iRound][es[iRound]][0]), hash_ctx_v, SHA256_DIGEST_LENGTH) != 0){
				assert(false);
			}


			// cmp with y
			T yRound[output_in_words];
			for(int i=0; i<output_in_words; i++){
				long int off3d = yp.index(i, iRound, 0);
				yRound[i] = yp.data[off3d] ^ yp.data[off3d+1] ^ yp.data[off3d+2];
			}
			assert(memcmp(yRound, y, output_in_words * sizeof(T))==0);
			delete[] res_v;
		}
	}catch (const std::runtime_error &e) {
		verification_ok = false;
		std::cout << "verification failed : " << e.what() << std::endl;
	}
	delete[] y;
	return verification_ok;
}

#endif /* INC_MPC_CORE_H_ */
