/*
 * MpcCore.cpp
 *
 *  Created on: Oct 7, 2016
 *      Author: ivan
 */

#include "assert.h"
#include "mpc_core.h"


//For compatibility with zkbpp
std::string zkboo_update_proof_commitment_string(const std::string &proof_commit, const unsigned char hash[ZKBOO_HASH_BYTES]){
	return proof_commit;
}


//  String format of the proof-response:
//
//  [NUMBER_OF_ROUNDS * 2 of MpcPartyView]      # MpcPartyView[]
std::string zkboo_convert_proof_response_to_string(const MpcProof z[]){
	std::vector<std::string> vector_res;
	// 4. MpcProof
	for(int i=0; i<ZKBOO_NUMBER_OF_ROUNDS; i++){
		for(int j=0; j<2; j++){
			std::vector<std::string> view_2string = MpcPartyView_to_string(z[i].pView[j]);
			vector_res.insert(vector_res.end(), view_2string.begin(), view_2string.end());
		}
	}
	std::string res = vectorstrings_to_string(vector_res);
	return res;
}


std::vector<std::string> zkboo_prove_response(const std::vector<std::string> &z_all, const unsigned char hash[ZKBOO_HASH_BYTES]){
	std::vector<std::string> res;
	int es[ZKBOO_NUMBER_OF_ROUNDS];
	extract_es_from_Challenge(es, hash);
	for(unsigned int i=0, j=0; i<z_all.size(); i+=6, j++){
		if (es[j]==0){
			res.push_back(z_all[i]);
			res.push_back(z_all[i+1]);

			res.push_back(z_all[i+2]);
			res.push_back(z_all[i+3]);
		}else if (es[j]==1){
			res.push_back(z_all[i+2]);
			res.push_back(z_all[i+3]);

			res.push_back(z_all[i+4]);
			res.push_back(z_all[i+5]);
		}else if (es[j]==2){
			res.push_back(z_all[i+4]);
			res.push_back(z_all[i+5]);

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
void zkboo_convert_input(MpcVariable<uint8_t>& x, const uint8_t &secret_input, const MpcPartyContext *context[3]){
	uint8_t shares[3];
	generate_random((unsigned char *)shares, 2*sizeof(uint8_t));
	shares[2] = secret_input ^ shares[0] ^ shares[1];
	x = MpcVariable<uint8_t>(shares, context);
}


std::string zkboo_extract_input_as_binary(const std::string &proof_view_part1, int input_len_bytes){
	// skip first 16 bytes of randomness and 4 byte for input size.
	int offset_input = ZKBOO_RND_TAPE_SEED_LEN + 1 * sizeof(uint32_t);
	assert(proof_view_part1.size() >= (unsigned int) (offset_input + input_len_bytes));
	return std::string(proof_view_part1, offset_input, input_len_bytes);
}

