/*
 * ZBP++ Core file.
 *
 * Originally copied from mpc_core.h, so that both version, ZKBoo and ZKB++, could co-exist.
 *
 *  Created on: November 15, 2017
 *      Author: ivan
 */

#ifndef INC_ZKBPP_CORE_H_
#define INC_ZKBPP_CORE_H_

#include "MpcVariable.h"
#include <openssl/sha.h>
#include <algorithm>
#include <sstream>
#include "assert.h"
#include "Matrix.h"

#include "mpc_core.h"


//  String format of the proof-commitment:
//
//  [4:input_size_bytes]  [4:output_size_bytes]  # header
//  [output_size_bytes * NUMBER_OF_ROUNDS * 3]  # yp
//  [NUMBER_OF_ROUNDS * 3 * SHA256_DIGEST_LEN]  # hash
//
template <typename T>   // output type, e.g. uint32_t
std::string zkbpp_convert_proof_commitment_to_string(int input_bytes, int output_len_bytes,
		//const T yp[][ZKBOO_NUMBER_OF_ROUNDS][3] /*IN*/ /*first dimention is output_in_words*/,
		const T yp[], // it is a contiguous memory region
		unsigned char hash[ZKBOO_NUMBER_OF_ROUNDS][3][ZKBOO_COMMITMENT_VIEW_LENGTH]){
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
	std::string hash_str((char *) hash, ZKBOO_NUMBER_OF_ROUNDS * 3 * ZKBOO_COMMITMENT_VIEW_LENGTH);
	vector_res.push_back(hash_str); // [2]

	std::string res = vectorstrings_to_string(vector_res);
	return res;
}

template <typename T>
void dump_proof_commit_full(const char* msg, const std::string &proof_commit_full){
	std::vector<std::string> vs = string_to_vectorstrings(proof_commit_full);

	printf("%s // size=%d\n", msg, (int)proof_commit_full.length());
	//1. header
	uint32_t * header = (uint32_t*) vs[0].data();
	uint32_t output_len = *(header+1);
	printf(" - 1. header = %s;  output_len=%d\n", format_memory(vs[0].data(), 8).c_str(), output_len);
	//2. yp
	printf(" - 2. T yp[words=0   ][R=0][3] = %s\n", format_memory(vs[1].data(), 3 * sizeof(T)).c_str());

	for(int iw=1; iw<4; iw++){
		printf(" -  . T yp[words=%d   ][R=0][3] = %s\n",
				iw,
				format_memory(vs[1].data()+(sizeof(T)*ZKBOO_NUMBER_OF_ROUNDS*(iw)), 3 * sizeof(T)).c_str());
	}
	//printf(" -  . T yp[words=last][R=0][3] = %s\n", format_memory(vs[1].data()+(sizeof(T)*ZKBOO_NUMBER_OF_ROUNDS*(output_len-1)), 3 * sizeof(T)).c_str());
	//3. hashes
	printf(" - 3. hash[R=0][3][SHA256] = %s\n", format_memory(vs[2].data(), 3 * ZKBOO_COMMITMENT_VIEW_LENGTH).c_str());

	printf(" -  . hash[R=1][3][SHA256] = %s\n", format_memory(vs[2].data() + (3 * ZKBOO_COMMITMENT_VIEW_LENGTH) * 1, 3 * ZKBOO_COMMITMENT_VIEW_LENGTH).c_str());
}



// exists only in zkbpp, not zkboo
//
//
//  [4:input_size_bytes]  [4:output_size_bytes]  # header
//  [output_size_bytes * NUMBER_OF_ROUNDS * 3]  # yp  <---- removed acc. to Opt.5
//  [NUMBER_OF_ROUNDS * 2 * SHA256_DIGEST_LEN]  # hash  <--- updated acc. to Opt.3
std::string zkbpp_update_proof_commitment_string(const std::string &proof_commit, const unsigned char hash[ZKBOO_HASH_BYTES]);


//  String format of the proof-response:
//
//  [NUMBER_OF_ROUNDS * 2 of MpcPartyView]      # MpcPartyView[]
std::string zkbpp_convert_proof_response_to_string(const MpcProof z[]);


template <typename T>   // output function type, e.g. uint32_t
void zkbpp_convert_string_to_proof(
			const std::vector<std::string> &proof_commit,
			const std::vector<std::string> &proof_vs,
			int output_words,
		const mpc::Matrix3D<T> &yp /*OUT*/, // equiv. of [][ZKBOO_NUMBER_OF_ROUNDS][3], where first dimension is output_in_words extracted from the proof
		unsigned char hash_2views[ZKBOO_NUMBER_OF_ROUNDS][2][ZKBOO_COMMITMENT_VIEW_LENGTH] /*OUT*/,
		MpcProof z[] /*OUT*/){

	//const char * data = proof_commit[1].data();
	assert(proof_commit[1].size() == 0); //Opt.5
	//assert(proof_commit[1].size() == sizeof(T) * output_words * ZKBOO_NUMBER_OF_ROUNDS * 3);
	//memcpy(&yp.data[0], data, sizeof(T) * output_words * ZKBOO_NUMBER_OF_ROUNDS * 3); // memory is contiguous, so we can write that

	assert(proof_commit[2].size() == ZKBOO_NUMBER_OF_ROUNDS * 2 * ZKBOO_COMMITMENT_VIEW_LENGTH);
	memcpy(hash_2views, proof_commit[2].data(), proof_commit[2].size());

	unsigned int index = 0;
	for(int i=0; i<ZKBOO_NUMBER_OF_ROUNDS; i++){
		//Opt.6.  Layout: [p1]p2--[p1p2]--p1p2
		// but we make it compatible to [p1](p2)--[p1p2]--p1p2, where (p2) is empty string

		assert(index+2 < proof_vs.size());
		z[i].pView[0] = string_to_MpcPartyView(proof_vs[index], proof_vs[index+1]);
		z[i].pView[1] = string_to_MpcPartyView(proof_vs[index+2], proof_vs[index+3]);
		index += 4;
	}
}

// splits x to 3 random parts that XOR to the original value
void zkbpp_convert_input(MpcVariable<uint8_t>& x, const uint8_t &secret_input, MpcPartyContext *context[3]);


template <typename T>   // output type, e.g. uint32_t
std::string zkbpp_prove_commit(
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

	unsigned char hashView[ZKBOO_NUMBER_OF_ROUNDS][3][ZKBOO_COMMITMENT_VIEW_LENGTH]; // commitment to each virtual mpc party computation

	for(int iRound=0; iRound<ZKBOO_NUMBER_OF_ROUNDS; iRound++){
		MpcPartyContext ctxArray[3];
		MpcPartyContext* ctx[3];

		MpcVariable<uint8_t> input_mpc[input_bytes];
		for(int ip=0; ip<3; ip++) {// ip = iParty
			ctx[ip] = &ctxArray[ip];
			InitMpcContext(ctx[ip], random_tape_len_in_bytes, false);
		}
		for(int ilen=0; ilen<input_bytes; ilen++){
			// Opt.1. The Share Function.
			zkbpp_convert_input(input_mpc[ilen], input[ilen], ctx); // input is split into 3 random parts

//			for(int ip=0; ip<3; ip++){
//				ctx[ip]->view.input.push_back(input_mpc[ilen].value(ip));
//			}
			// Opt.2. Not including input shares for 1st and 2nd views.
			ctx[2]->view.input.push_back(input_mpc[ilen].value(2));
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
			//DEPRECATED add hash commit to the view instead of contiguous region, because later we won't need one of them due to Opt.3
			//memcpy(ctx[ip][iRound].commitment, hashView[iRound][ip], ZKBOO_COMMITMENT_VIEW_LENGTH);
		}
		if (iRound == 0){
			printf("used randomness elements: %d\n",  ctx[0]->randomnessUsed);
		}

		// store all views into vector z
		for(int iParty=0; iParty<3; iParty++){
			std::vector<std::string> view_str = MpcPartyView_to_string(ctx[iParty]->view);
			zkboo_proof_3parts.insert(zkboo_proof_3parts.end(), view_str.begin(), view_str.end());
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

	std::string proof_com_full = zkbpp_convert_proof_commitment_to_string(input_bytes, output_len_bytes, yp.data, hashView);
	delete[] y;
	return proof_com_full;
}

std::vector<std::string> zkbpp_prove_response(const std::vector<std::string> &z_all, const unsigned char hash[ZKBOO_HASH_BYTES]);


//Opt.3 Not including commitments
void zkbpp_Opt3_3view_to_2view(
		unsigned char * dest_hash_2view /*[ZKBOO_NUMBER_OF_ROUNDS][2][ZKBOO_COMMITMENT_VIEW_LENGTH]*/,
		const unsigned char * source_hash_3view /*[ZKBOO_NUMBER_OF_ROUNDS][3][ZKBOO_COMMITMENT_VIEW_LENGTH]*/,
		int* es /*ZKBOO_NUMBER_OF_ROUNDS*/);

//returns proof commit
template <typename T>   // output function type, e.g. uint32_t
std::string zkbpp_fake_prove(
			std::vector<std::string> &zkboo_proof_2parts /*OUT*/ /*for 2 out of 3 in {x_1,x_2,x_3}*/,
		const char * function_name,
		const unsigned char hash[ZKBOO_HASH_BYTES] /* IN */,
		int input_bytes,
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
	unsigned char hash_3View[ZKBOO_NUMBER_OF_ROUNDS][3][ZKBOO_COMMITMENT_VIEW_LENGTH]; // commitment to each virtual mpc party computation
	//unsigned char hash_2View[ZKBOO_NUMBER_OF_ROUNDS][3][ZKBOO_COMMITMENT_VIEW_LENGTH]; // for output

	//FIXME T instead of uint32_t?
	//FIXME explain why we need fake_randomness?
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
			//generate_random((unsigned char *)shares, 2*sizeof(uint8_t)); //FIXME!!! Opt.1

			for(int ip=0; ip<2; ip++){
				if (es[iRound]+ip != 2){
					shares[ip] = (uint8_t) (nextRandom32_fromCtx(ctx[iRound][ip]) & 0xFF);
				}else{
					generate_random((unsigned char *) &shares[ip], sizeof(uint8_t));
				}
			}
			//shares[0] = (uint8_t) (nextRandom32_fromCtx(ctx[iRound][es[iRound]]) & 0xFF);
			//shares[1] = secret_input ^ shares[0] ^ shares[1];

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
			CommitMpcContext((unsigned char*) &hash_3View[iRound][(es[iRound] + ip) % 3], ctx[iRound][ip]);

			/*
			printf("C++ | Committing in fake proof ZKBoo: ");
			dump_memory((const char *)(unsigned char*) &hashView[iRound][(es[iRound] + ip) % 3], ZKBOO_COMMITMENT_VIEW_LENGTH);
			printf(" with randomness: ");
			dump_memory((const char *) &ctx[iRound][ip]->view.rnd_tape_seed, 16);
			printf("\n");
			*/
		}
		generate_random((unsigned char*) &hash_3View[iRound][(es[iRound] + 2) % 3], ZKBOO_COMMITMENT_VIEW_LENGTH);
		delete[] res;
	}
	printf("fake proof: used randomness elements: %d\n",  ctx[0][0]->randomnessUsed);

	// store all views into vector z
	for(int iRound=0; iRound<ZKBOO_NUMBER_OF_ROUNDS; iRound++){
		//Opt.6 Not including full views
		std::vector<std::string> view_vs1 = MpcPartyView_to_string(ctx[iRound][0]->view);
		zkboo_proof_2parts.push_back(view_vs1[0]);
		zkboo_proof_2parts.push_back(std::string());
		std::vector<std::string> view_vs2 = MpcPartyView_to_string(ctx[iRound][1]->view);
		zkboo_proof_2parts.push_back(view_vs2[0]);
		zkboo_proof_2parts.push_back(view_vs2[1]);

	}

	//zkbpp_Opt3_3view_to_2view((unsigned char*)hash_2View, (const unsigned char*)hash_3View, es);

	std::string proof_com_full = zkbpp_convert_proof_commitment_to_string(input_bytes, output_len_bytes, yp.data, hash_3View);
	//std::string proof_com = zkbpp_update_proof_commitment_string(proof_com_full, hash);
	return proof_com_full;
}


// if verification succeeds, it returns proov_commit_recomputed required for H function,
// otherwise it returns empty string.
template <typename T>   // output type, e.g. uint32_t
std::string zkbpp_verify(const char * function_name,
		const unsigned char hash_v[ZKBOO_HASH_BYTES] /*IN*/,
		int input_bytes,
		const char * inputpub, int inputpub_len_bytes,
		const char * output, int output_len_bytes,
		int random_tape_len_in_bytes,
		void (*func_verif)(const MpcVariableVerify<uint8_t>* input, int input_len_bytes,
				const uint8_t inputpub[], int inputpub_len_bytes,
				MpcVariableVerify<T>* z, int output_in_words),
		const std::string& proof_commit /*IN*/,
		const std::vector<std::string> &z_str /*IN*/){
	std::string res;

	std::vector<std::string> proof_commit_vs = string_to_vectorstrings(proof_commit);
	std::string header_str = proof_commit_vs[0];
	//uint32_t* inputsize_ptr = (uint32_t*) header_str.data();
	uint32_t* outputsize_ptr = (uint32_t*) header_str.data() + 1; //next 4 bytes

	int output_in_words = *outputsize_ptr / sizeof(T);
	mpc::Matrix3D<T> yp(output_in_words, ZKBOO_NUMBER_OF_ROUNDS, 3);

	unsigned char hashViews2[ZKBOO_NUMBER_OF_ROUNDS][2 /*Opt.3*/][ZKBOO_COMMITMENT_VIEW_LENGTH];
	unsigned char * hashViews2_ptr = (unsigned char *) hashViews2;
	MpcProof zp[ZKBOO_NUMBER_OF_ROUNDS];
	zkbpp_convert_string_to_proof(proof_commit_vs, z_str, output_in_words, yp, hashViews2, zp);

	//we need this as output
	char hashViews3[ZKBOO_NUMBER_OF_ROUNDS * 3 *ZKBOO_COMMITMENT_VIEW_LENGTH];
	int offset3 = 0;
	int offset2 = 0; // for hashViews2


	//Opt.5 not including output shares, it should be recomputed by the verifier
	T* expected_output = (T*) output;
//	for(int offset=0; offset<output_in_words; offset++){
//		for(int i=0; i<ZKBOO_NUMBER_OF_ROUNDS; i++){
//			long int off3d = yp.index(offset, i, 0);
//			T y_received = yp.data[off3d] ^ yp.data[off3d+1] ^ yp.data[off3d+2]; //equiv. to yp[offset][i][0] ^ yp[offset][i][1] ^ yp[offset][i][2];
//			if (y_received != *(expected_output+offset)){
//				//printf("C++ | expected output does not match the received. verify returns false\n"); //FIXME connect with view32/64
//				return res; //empty string
//			}
//		}
//	}

	int es[ZKBOO_NUMBER_OF_ROUNDS];
	extract_es_from_Challenge(es, hash_v);

//	T* y = new T[output_in_words];
//	for(int i=0; i<output_in_words; i++){
//		long int off3d = yp.index(i, 0, 0);
//		y[i] = yp.data[off3d] ^ yp.data[off3d+1] ^ yp.data[off3d+2]; //equiv. y[i] = yp[i][0][0] ^ yp[i][0][1] ^ yp[i][0][2];
//	}

	MpcPartyContext ctxArray[ZKBOO_NUMBER_OF_ROUNDS][2];
	MpcPartyContext* ctx[ZKBOO_NUMBER_OF_ROUNDS][2];

	bool verification_ok = true;
	try{
		for(int iRound=0; iRound < ZKBOO_NUMBER_OF_ROUNDS; iRound++){
			for(int i=0; i<2; i++){
				assert((unsigned int)input_bytes == zp[iRound].pView[i].input.size() || 0 == zp[iRound].pView[i].input.size());
				ctx[iRound][i] = &ctxArray[iRound][i];
				//prepare context
				InitMpcContext(ctx[iRound][i], zp[iRound].pView[i].rnd_tape_seed, random_tape_len_in_bytes, true);
				ctx[iRound][i]->view = zp[iRound].pView[i];
				ctx[iRound][i]->verifier_counter32 = 0;
				ctx[iRound][i]->verifier_counter64 = 0;
				if (0 == zp[iRound].pView[i].input.size()){
					// Opt.2. Not including input shares, so we need to regenerate.
					for (int i_input=0; i_input<input_bytes; i_input++){
						ctx[iRound][i]->view.input.push_back((uint8_t) (nextRandom32_fromCtx(ctx[iRound][i]) & 0xFF));
					}
				}
			}
			// prepare MpcVariableVerify
			MpcVariableVerify<uint8_t> input_v[input_bytes];
			MpcVariableVerify<T>* res_v = new MpcVariableVerify<T>[output_in_words];

			for(int iw=0; iw<input_bytes; iw++){
				uint8_t xp[2];
				for(int i=0; i<2; i++){
					xp[i] = ctx[iRound][i]->view.input[iw];
				}
				input_v[iw] = MpcVariableVerify<uint8_t>(xp, (const MpcPartyContext**)ctx[iRound]);
			}

			(*func_verif)(input_v, input_bytes, (uint8_t*)inputpub, inputpub_len_bytes, res_v, output_in_words); // +-+-+-+-+
			// the fact that the function did not throw any exception at this point means that
			// the output part of ctx[0].view was correctly verified

			//cmp local output with the views provided by the prover
			bool reconstruct_required = zkbpp_is_reconstruct_required((const MpcPartyContext**)ctx[iRound]);
			for(int ip=0; ip<2; ip++){
				for(int iw=0; iw<output_in_words; iw++){
					if (sizeof(T)==4){
						if (!reconstruct_required || ip!=0){
							assert (ctx[iRound][ip]->view.output32[ctx[iRound][ip]->verifier_counter32] == res_v[iw].value(ip));
						}else{
							ctx[iRound][ip]->view.output32.push_back(res_v[iw].value(ip));
						}
						ctx[iRound][ip]->verifier_counter32++;
					}else if (sizeof(T)==8){
						if (!reconstruct_required || ip!=0){
							assert (ctx[iRound][ip]->view.output64[ctx[iRound][ip]->verifier_counter64] == res_v[iw].value(ip));
						}else{
							ctx[iRound][ip]->view.output64.push_back(res_v[iw].value(ip));
						}
						ctx[iRound][ip]->verifier_counter64++;
					}else {
						throw std::runtime_error("not supported");
					}
					//FIXME check? or just H
				}
			}

			//verify that MpcContext hash commitment was computed correctly and matches the challenge value
			unsigned char hash_ctx_v[ZKBOO_COMMITMENT_VIEW_LENGTH];
			assert (ctx[iRound][0]->view.output32.size() == ctx[iRound][0]->verifier_counter32);
			assert (ctx[iRound][0]->view.output64.size() == ctx[iRound][0]->verifier_counter64);
			CommitMpcContext(hash_ctx_v, ctx[iRound][0]);

			/*
			printf("C++ | Committing in verify proof ZKBoo: ");
				dump_memory((const char *) hash_ctx_v, ZKBOO_COMMITMENT_VIEW_LENGTH);
				printf(" with randomness: ");
				dump_memory((const char *) ctx[iRound][0]->view.rnd_tape_seed, 16);
			printf("\n");
			*/

			/*
			printf("C++ | Hashes in ZKBoo do not match! Expected ");
				dump_memory((const char *)&(hashViews[iRound][es[iRound]][0]), ZKBOO_COMMITMENT_VIEW_LENGTH);
				printf(", but received ");
				dump_memory((const char *)hash_ctx_v, ZKBOO_COMMITMENT_VIEW_LENGTH);
			printf("\n");
			*/


			//Opt.3. Not including 1 our of 3 commitments for the view that can be recomputed.
//			if (memcmp(&(hashViews2[iRound][es[iRound]][0]), hash_ctx_v, ZKBOO_COMMITMENT_VIEW_LENGTH) != 0){
//				assert(false);
//			}
			//for(int iP=0; iP<3; iP++){
				if (es[iRound]==0){
					memcpy(hashViews3+offset3, hash_ctx_v, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;

					memcpy(hashViews3+offset3, hashViews2_ptr + offset2, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
					offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;

					memcpy(hashViews3+offset3, hashViews2_ptr + offset2, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
					offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;
				}else if (es[iRound]==1){
					memcpy(hashViews3+offset3, hashViews2_ptr + offset2, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
					offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;

					memcpy(hashViews3+offset3, hash_ctx_v, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;

					memcpy(hashViews3+offset3, hashViews2_ptr + offset2, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
					offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;
				} else { // ==2
					memcpy(hashViews3+offset3, hashViews2_ptr + offset2, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
					offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;

					memcpy(hashViews3+offset3, hashViews2_ptr + offset2, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
					offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;

					memcpy(hashViews3+offset3, hash_ctx_v, ZKBOO_COMMITMENT_VIEW_LENGTH);
					offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
				}

//				if (iP==es[iRound]){
//					memcpy(hashViews3+offset3, hash_ctx_v, ZKBOO_COMMITMENT_VIEW_LENGTH);
//				}else{
//					memcpy(hashViews3+offset3, hashViews2_ptr + offset2, ZKBOO_COMMITMENT_VIEW_LENGTH);
//					offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;
//				}
//				offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
			//}

			//Opt.5. Not including output shares. They should be recomputed.
			for(int iw=0; iw<output_in_words; iw++){
				long int off3d = yp.index(iw, iRound, 0);
				if (es[iRound]==0){
					yp.data[off3d] = res_v[iw].value(0);
					yp.data[off3d+1] = res_v[iw].value(1);
					yp.data[off3d+2] = expected_output[iw] ^ yp.data[off3d] ^ yp.data[off3d+1];
				}else if (es[iRound]==1){
					yp.data[off3d+1] = res_v[iw].value(0);
					yp.data[off3d+2] = res_v[iw].value(1);
					yp.data[off3d] = expected_output[iw] ^ yp.data[off3d+1] ^ yp.data[off3d+2];
				}else{
					yp.data[off3d+2] = res_v[iw].value(0);
					yp.data[off3d] = res_v[iw].value(1);
					yp.data[off3d+1] = expected_output[iw] ^ yp.data[off3d+2] ^ yp.data[off3d];
				}
			}


			// cmp with y---- not needed anymore acc. to Opt.5
//			T yRound[output_in_words];
//			for(int i=0; i<output_in_words; i++){
//				long int off3d = yp.index(i, iRound, 0);
//				yRound[i] = yp.data[off3d] ^ yp.data[off3d+1] ^ yp.data[off3d+2];
//			}
//			assert(memcmp(yRound, y, output_in_words * sizeof(T))==0);
			delete[] res_v;
		}
	}catch (const std::runtime_error &e) {
		verification_ok = false;
		std::cout << "verification failed : " << e.what() << std::endl;
	}
	if (verification_ok){
		//prepare proof_commit_reconstructed
		//proof_commit_vs[0] -- header, remains intact
		proof_commit_vs[1] = std::string((const char *)yp.data, yp.size_bytes());
		proof_commit_vs[2] = std::string(hashViews3, ZKBOO_NUMBER_OF_ROUNDS * 3 * ZKBOO_COMMITMENT_VIEW_LENGTH);
		res = vectorstrings_to_string(proof_commit_vs); //proof_commit_recomputed_str
	}
	//delete[] y;
	return res;
}


std::string zkbpp_extract_input_as_binary(const std::string &proof_view_part1, int input_len_bytes);


#endif /* INC_ZKBPP_CORE_H_ */

