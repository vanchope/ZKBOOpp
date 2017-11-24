/*
 * MpcCore.cpp
 *
 *  Created on: Oct 7, 2016
 *      Author: ivan
 */

#include "assert.h"
#include "zkbpp_core.h"



//  String format of the proof-response:
//
//  [NUMBER_OF_ROUNDS * 2 of MpcPartyView]      # MpcPartyView[]
std::string zkbpp_convert_proof_response_to_string(const MpcProof z[]){
	std::vector<std::string> vector_res;
	// 4. MpcProof
	for(int i=0; i<ZKBOO_NUMBER_OF_ROUNDS; i++){
		//Opt.6 Not including full views
		std::vector<std::string> view_vs1 = MpcPartyView_to_string(z[i].pView[0]);
		vector_res.push_back(view_vs1[0]);
		vector_res.push_back(std::string());

		std::vector<std::string> view_vs2 = MpcPartyView_to_string(z[i].pView[1]);
		vector_res.push_back(view_vs2[0]);
		vector_res.push_back(view_vs2[1]);
	}
	std::string res = vectorstrings_to_string(vector_res);
	return res;
}


std::vector<std::string> zkbpp_prove_response(const std::vector<std::string> &z_all, const unsigned char hash[ZKBOO_HASH_BYTES]){
	std::vector<std::string> res;
	int es[ZKBOO_NUMBER_OF_ROUNDS];
	extract_es_from_Challenge(es, hash);
	for(unsigned int i=0, j=0; i<z_all.size(); i+=6, j++){
		//Opt.6 Not including full views --- already taken care by zkbpp_convert_proof_response_to_string
		if (es[j]==0){
			res.push_back(z_all[i]);
			res.push_back(z_all[i+1]);
			//res.push_back(std::string());

			res.push_back(z_all[i+2]);
			res.push_back(z_all[i+3]);
		}else if (es[j]==1){
			res.push_back(z_all[i+2]);
			res.push_back(z_all[i+3]);
			//res.push_back(std::string());

			res.push_back(z_all[i+4]);
			res.push_back(z_all[i+5]);
		}else if (es[j]==2){
			res.push_back(z_all[i+4]);
			res.push_back(z_all[i+5]);
			//res.push_back(std::string());

			res.push_back(z_all[i]);
			res.push_back(z_all[i+1]);
		}else{
			throw std::runtime_error("unexpected value");
		}
	}
	return res;
}

// --------------------------------------

//FIXME bulk convert to save the number of calls to RAND_bytes
void zkbpp_convert_input(MpcVariable<uint8_t>& x, const uint8_t &secret_input, MpcPartyContext *context[3]){
	uint8_t shares[3];
	//Opt.1. The Share Function.
	shares[0] = (uint8_t) (nextRandom32_fromCtx(context[0]) & 0xFF);
	shares[1] = (uint8_t) (nextRandom32_fromCtx(context[1]) & 0xFF);
	shares[2] = secret_input ^ shares[0] ^ shares[1];
	x = MpcVariable<uint8_t>(shares, (const MpcPartyContext **) context);
}




// only in zkbpp, Opt.3 + Opt.5
// Every third commitment is removed from the proof, as it can be recomputed by the verifier
std::string zkbpp_update_proof_commitment_string(const std::string &proof_commit_full, const unsigned char hash[ZKBOO_HASH_BYTES]){
	std::vector<std::string> vs = string_to_vectorstrings(proof_commit_full);
	const char * hash_views = vs[2].data(); // ZKBOO_NUMBER_OF_ROUNDS * 3 * ZKBOO_COMMITMENT_VIEW_LENGTH

	//Opt.3. Not including every third commitment, for which the verifier can reconstruct its value.
	int es[ZKBOO_NUMBER_OF_ROUNDS];
	extract_es_from_Challenge(es, hash);


	char hash_2views[ZKBOO_NUMBER_OF_ROUNDS * 2 * ZKBOO_COMMITMENT_VIEW_LENGTH];

	zkbpp_Opt3_3view_to_2view((unsigned char*)hash_2views, (const unsigned char*)hash_views, es);
//	unsigned int offset3 = 0;
//	unsigned int offset2 = 0;
//	for(int iRound=0; iRound<ZKBOO_NUMBER_OF_ROUNDS; iRound++){
//		for(int ip=0; ip<3; ip++){
//			if (ip!=es[iRound]){
//				memcpy(hash_2views+offset2, hash_views+offset3, ZKBOO_COMMITMENT_VIEW_LENGTH);
//				offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;
//			}
//			offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
//		}
//	}

	vs[1] = std::string(); //Opt.5
	vs[2] = std::string(hash_2views, ZKBOO_NUMBER_OF_ROUNDS * 2 * ZKBOO_COMMITMENT_VIEW_LENGTH);
	std::string res = vectorstrings_to_string(vs);
	return res;
}

void zkbpp_Opt3_3view_to_2view(
		unsigned char * dest_hash_2view /*[ZKBOO_NUMBER_OF_ROUNDS][2][ZKBOO_COMMITMENT_VIEW_LENGTH]*/,
		const unsigned char * source_hash_3view /*[ZKBOO_NUMBER_OF_ROUNDS][3][ZKBOO_COMMITMENT_VIEW_LENGTH]*/,
		int* es /*ZKBOO_NUMBER_OF_ROUNDS*/){
	int offset2 = 0;
	int offset3 = 0;
	for (int iRound = 0; iRound < ZKBOO_NUMBER_OF_ROUNDS; ++iRound) {
		for(int ip=0; ip<3; ip++){
			if (ip!=es[iRound]){
				memcpy(dest_hash_2view+offset2, source_hash_3view+offset3, ZKBOO_COMMITMENT_VIEW_LENGTH);
				offset2 += ZKBOO_COMMITMENT_VIEW_LENGTH;
			}
			offset3 += ZKBOO_COMMITMENT_VIEW_LENGTH;
		}
	}
}


std::string zkbpp_extract_input_as_binary(const std::string &proof_view_part1, int input_len_bytes){
	//assert(proof_view_part1.length() >= ZKBOO_RND_TAPE_SEED_LEN);
	int offset_input = ZKBOO_RND_TAPE_SEED_LEN + 1 * sizeof(uint32_t);
	// Two cases: either randomness is needed to be re-generated, or take it from input part of the proof-view.
	if(proof_view_part1.size() < (unsigned int) (offset_input + input_len_bytes)){
		uint8_t res[input_len_bytes];
		std::vector<uint32_t> v;
		// one uint32_t gives 1 byte of input randomness; this is just to simplify the algorithm. FIXME
		// add 16 to round up
		getAllRandomness((const unsigned char*) proof_view_part1.data(), v, 8 * (input_len_bytes * sizeof(uint32_t)) + 128);
		for(int i=0; i<input_len_bytes; i++){
			res[i] = (uint8_t) (v[i] & 0xFF);
		}
		return std::string((const char*) res, input_len_bytes);
	} else {
		return std::string(proof_view_part1, offset_input, input_len_bytes);
	}
}


