/*
 * MpcCore.cpp
 *
 *  Created on: Oct 7, 2016
 *      Author: ivan
 */

#include "assert.h"
#include "mpc_core.h"

void dump_memory(const char * data, int len){
	unsigned int split1, split2;
	if (len <= 100){
		split1 = len / 2;
		split2 = split1;
	}else{
		split1 = 32;
		split2 = len - 32;
	}

	for(unsigned int i=0; i<split1; i++){
		printf("%02x", (uint8_t)data[i]);
	}
	if (split1 != split2){
		printf("...(%d more)...", split2-split1);
	}
	for(int i=split2; i<len; i++){
		printf("%02x", (uint8_t)data[i]);
	}
}


//  String format of the proof-response:
//
//  [NUMBER_OF_ROUNDS * 2 of MpcPartyView]      # MpcPartyView[]
std::string convert_proof_response_to_string(const MpcProof z[]){
	std::vector<std::string> vector_res;
	// 4. MpcProof
	for(int i=0; i<ZKBOO_NUMBER_OF_ROUNDS; i++){
		for(int j=0; j<2; j++){
			std::string view_string = MpcPartyView_to_string(z[i].pView[j]);
			vector_res.push_back(view_string);
		}
	}
	std::string res = vectorstrings_to_string(vector_res);
	return res;
}


std::vector<std::string> zkboo_prove_response(const std::vector<std::string> &z_all, const unsigned char hash[ZKBOO_HASH_BYTES]){
	std::vector<std::string> res;
	int es[ZKBOO_NUMBER_OF_ROUNDS];
	extract_es_from_Challenge(es, hash);
	for(unsigned int i=0, j=0; i<z_all.size(); i+=3, j++){
		if (es[j]==0){
			res.push_back(z_all[i]);
			res.push_back(z_all[i+1]);
		}else if (es[j]==1){
			res.push_back(z_all[i+1]);
			res.push_back(z_all[i+2]);
		}else if (es[j]==2){
			res.push_back(z_all[i+2]);
			res.push_back(z_all[i]);
		}else{
			throw std::runtime_error("unexpected value");
		}
	}
	return res;
}

