/*
 * test_utility.cpp
 *
 *  Created on: Oct 27, 2016
 *      Author: ivan
 */
#include "test_utility.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include <sstream>

#include "mpc_core.h"
#include "zkbpp_core.h"

char* fetch_next_str(int argc, char* argv[], int &i){
	if (i+1 < argc){
		i++;
		return argv[i];
	}else{
		printf("Input was not specified!\n");
		exit(1);
	}
}


int fetch_next_int(int argc, char* argv[], int &i){
	if (i+1 < argc){
		i++;
		int res;
		sscanf(argv[i], "%d", &res);
		return res;
	}else{
		printf("Input was not specified!\n");
		exit(1);
	}
}

void unknown_arg(const char * arg){
	std::stringstream sstr;
	sstr << "unknown argument: " << arg << std::endl;
	printf("%s\n",sstr.str().c_str());
	exit(1);
}

long long get_vector_string_size(const std::vector<std::string> &v){
	long long size = 0;
	for(unsigned int i=0; i<v.size(); i++){
		size += v[i].size();
	}
	return size;
}

// return 0 if ok, otherwise 1.
bool process_argv(program_params & params, int argc, char * argv[]){
	params.unit_test = false;
	params.run_prover = true;
	params.run_verifier = false;
	params.repetitions = 1;
	params.input = "";
	params.algorithm = "zkboo";
	if (argc<=1){
		printf("Usage: %s [-p] [-v] repetitions\n", argv[0]);
		printf("   or\n");
		printf("       %s [-u]\n", argv[0]);
		printf("   where\n");
		printf("   -alg <...>         Algorithm, either zkboo or zkbpp (by default zkboo) \n");
		printf("   -p                 Run prover (always on)\n");
		printf("   -v                 Run verifier (by default off)\n");
		printf("   -input <...>       Input message (by default empty string)\n");
		if (params.outputlen_applicable)
		printf("   -outputlen <...>   Output length in bytes (default %d)\n", params.outputlen_bytes);
		printf("   -rep <...>         Integer, Number of iterations\n");
		printf("   -u                 Unittest. All other inputs are ignored.\n");
		printf("   -log <...>         Log level. 0=error,2=info,4=debug (default 0).\n");
		if (!params.outputlen_applicable)
		printf("\n    Note: -outputlen is not supported.\n");
		exit(0);
	}
	for(int i=1; i<argc; i++){
		if (argv[i][0] == '-'){
			if (strcmp(&argv[i][1],"alg")==0){
				params.algorithm = fetch_next_str(argc, argv, i);
			}else if (strcmp(&argv[i][1],"p")==0){
				params.run_prover = true;
			}else if (strcmp(&argv[i][1],"v")==0){
				params.run_verifier = true;
			}else if (strcmp(&argv[i][1],"u")==0){
				params.unit_test = true;
			}else if (strcmp(&argv[i][1],"input")==0){
				params.input = fetch_next_str(argc, argv, i);
			}else if (strcmp(&argv[i][1],"rep")==0){
				params.repetitions = fetch_next_int(argc, argv, i);
			}else if (strcmp(&argv[i][1],"log")==0){
				params.log_level = fetch_next_int(argc, argv, i);
			}else  if (params.outputlen_applicable && strcmp(&argv[i][1],"outputlen")==0){
				params.outputlen_bytes = fetch_next_int(argc, argv, i);
			}else{
				unknown_arg(argv[i]);
			}
		}else{
			unknown_arg(argv[i]);
		}
	}
	//validation
	if (strcmp(params.algorithm,"zkboo")!=0 &&
			strcmp(params.algorithm,"zkbpp")!=0){
		printf("unsupported algorithm %s\n", params.algorithm);
		return 1;
	}
	if (!params.unit_test){
		printf("Log level (0=error,2=info,4=debug) = %d\n", params.log_level);
		printf("Algorithm   = %s\n", params.algorithm);
		printf("Repetitions = %d\n", params.repetitions);
		printf("Run prover  = (always) yes\n");
		printf("Run verifier (y/n) = %d\n", params.run_verifier);
		printf("Input (%zd bytes): %s\n", strlen(params.input), params.input);
		if (params.outputlen_bytes > 0){
			printf("Output len (in bytes): %d\n", params.outputlen_bytes);
		}else{
			printf("Output len (in bytes): is not specified\n");
		}
	}
	return 0;
}

template <typename TOUT>  // TOUT = [T32 | T64], represents the output type
int main_with_command_line(const program_params &params, const char* func_name,
		void (*f_plain)(
			const uint8_t input[],
			int input_len_bytes,
			const uint8_t input_pub[],
			int input_pub_len_bytes,
			TOUT output[],
			int output_words),
		void (*f_prove)(
			const MpcVariable<uint8_t> input[],
			int input_len_bytes,
			const uint8_t input_pub[],
			int input_pub_len_bytes,
			MpcVariable<TOUT> output[],
			int output_words),
		void (*f_verify)(
			const MpcVariableVerify<uint8_t> input[],
			int input_len_bytes,
			const uint8_t input_pub[],
			int input_pub_len_bytes,
			MpcVariableVerify<TOUT> output[],
			int output_words),
		int (*func_random_tape_len_in_bytes)(
			int inputlen_bytes,
			int outputlen_bytes) ){

	if (params.unit_test)
		return 1; // unittest is not supported here.

	printf("ZKBOO_NUMBER_OF_ROUNDS = %d\n", ZKBOO_NUMBER_OF_ROUNDS);
	bool is_ZKBOO = (strcmp(params.algorithm,"zkboo")==0);
	//bool is_ZKBPP = (strcmp(params.algorithm,"zkbpp")==0);


	// plain output
	int output_words = params.outputlen_bytes / sizeof(TOUT);
	int input_len_bytes = strlen(params.input);
	TOUT * output_plain = new TOUT[output_words];
	(*f_plain)((uint8_t *)params.input, input_len_bytes, NULL, 0, output_plain, output_words);
	debug_func(func_name, params.input, input_len_bytes, NULL, 0, output_plain, output_words);


	// to achieve better performance, it should be function-specific
	int random_tape_len_in_bytes = (*func_random_tape_len_in_bytes)(input_len_bytes, params.outputlen_bytes);

	int outputlen_bytes = params.outputlen_bytes==0? 16 : params.outputlen_bytes;
	// prove and verify algorithms use string types, to connect later with python

	//Prove real
	for(int iRep=0; iRep<params.repetitions; iRep++){
		// prove part
		std::vector<std::string> z_all;
		std::string proof_commit_full;

		if (is_ZKBOO){
			proof_commit_full = zkboo_prove_commit<TOUT>(z_all, func_name, params.input, strlen(params.input),
					NULL, 0,
					(char *)output_plain, outputlen_bytes,
					random_tape_len_in_bytes, (*f_prove));
		}else{  // other cases are excluded already. It is ZKBPP.
			//Opt. 1: THe Share Function.
			proof_commit_full = zkbpp_prove_commit<TOUT>(z_all, func_name, params.input, strlen(params.input),
					NULL, 0,
					(char *)output_plain, outputlen_bytes,
					random_tape_len_in_bytes + input_len_bytes * sizeof(uint32_t), (*f_prove));
			// For simplicity, we provide 4 bytes of randomness for 1 byte of input, thus leading to 4x overhead,
			// but this is negligible compare to the rest of the randomness used in the protocol.
		}

		printf("Generated proof-commit-full with length %d bytes,  Z_ALL  length is %lld bytes.\n",
				(int) proof_commit_full.size(), get_vector_string_size(z_all));

		// At this point we need to generated the challenge.
		unsigned char hash_p[ZKBOO_HASH_BYTES];
		GenChallengeROM_from_single_proof(hash_p, proof_commit_full);

		std::vector<std::string> z;
		std::string proof_commit_updated; // after challenge is known
		if (is_ZKBOO){
			z = zkboo_prove_response(z_all, hash_p);
			// proof_commit_updated  = proof_commit_full
			proof_commit_updated = zkboo_update_proof_commitment_string(proof_commit_full, hash_p);
		}else {
			//Opt.3 update proof_commit
			z = zkbpp_prove_response(z_all, hash_p);
			proof_commit_updated = zkbpp_update_proof_commitment_string(proof_commit_full, hash_p);
		} // other cases are excluded already

		printf("Computed proof-commit-for-verifier with length %d bytes.\n",
						(int) proof_commit_updated.size());
		printf("Computed response (without proof_commit), length %lld bytes.\n", get_vector_string_size(z));


		long long total_proof_size = proof_commit_updated.size() + get_vector_string_size(z);
		printf("total proof size = %lld,  amplification factor = %f\n", total_proof_size, (double)total_proof_size / outputlen_bytes);

		if (params.run_verifier){
			unsigned char hash_v[ZKBOO_HASH_BYTES];

			std::string proof_commit_reconstructed;
			if (is_ZKBOO){
				proof_commit_reconstructed = zkboo_verify<TOUT>(func_name, hash_p, input_len_bytes, NULL, 0,
						(char *) output_plain, outputlen_bytes, random_tape_len_in_bytes,
						(*f_verify), proof_commit_updated, z);
			}else{
				proof_commit_reconstructed = zkbpp_verify<TOUT>(func_name, hash_p, input_len_bytes, NULL, 0,
						(char *) output_plain, outputlen_bytes, random_tape_len_in_bytes,
						(*f_verify), proof_commit_updated, z);
			} // other cases are excluded already

			if (proof_commit_reconstructed.length() < 1){
				printf("NOT VERIFIED!");
				return 1;
			}

			GenChallengeROM_from_single_proof(hash_v, proof_commit_reconstructed);
			// compare with hash_p
//			int es[ZKBOO_NUMBER_OF_ROUNDS];
//			extract_es_from_Challenge(es, hash_p);
//			printf("(prover) es[0] = %d\n", es[0]);
//			dump_proof_commit_full<TOUT>("proof_commit_full", proof_commit_full);
//			dump_proof_commit_full<TOUT>("proof_commit_reconsstructed", proof_commit_reconstructed);
			assert(memcmp(hash_v, hash_p, ZKBOO_HASH_BYTES) == 0);
		}
	}

	//Prove fake
	for(int iRep=0; iRep<params.repetitions; iRep++){
		unsigned char hash_p[ZKBOO_HASH_BYTES];
		generate_random(hash_p, ZKBOO_HASH_BYTES);
		// prove part
		std::vector<std::string> z_2parts;
		std::string proof_commit;
		std::string proof_commit_updated;

		if (is_ZKBOO){
			proof_commit = zkboo_fake_prove<TOUT>(z_2parts, func_name, hash_p, strlen(params.input),
					NULL, 0,
					(char *)output_plain, outputlen_bytes,
					random_tape_len_in_bytes, (*f_verify));
			proof_commit_updated = zkboo_update_proof_commitment_string(proof_commit, hash_p);
		}else{
			proof_commit = zkbpp_fake_prove<TOUT>(z_2parts, func_name, hash_p, strlen(params.input),
					NULL, 0,
					(char *)output_plain, outputlen_bytes,
					random_tape_len_in_bytes, (*f_verify));
			proof_commit_updated = zkbpp_update_proof_commitment_string(proof_commit, hash_p);
		}
		printf("Generated proof-commit with length %d bytes\n", (int) proof_commit.size());

		if (params.run_verifier){
			std::string proof_commit_reconstructed;

			if (is_ZKBOO){
				proof_commit_reconstructed = zkboo_verify<TOUT>(func_name, hash_p,
						input_len_bytes, NULL, 0,
						(char *) output_plain, outputlen_bytes, random_tape_len_in_bytes,
						(*f_verify), proof_commit_updated, z_2parts);
			}else{
				proof_commit_reconstructed = zkbpp_verify<TOUT>(func_name, hash_p,
						input_len_bytes, NULL, 0,
						(char *) output_plain, outputlen_bytes, random_tape_len_in_bytes,
						(*f_verify), proof_commit_updated, z_2parts);
			}

			if (proof_commit_reconstructed.length() < 1){
				printf("NOT VERIFIED!");
				return 1;
			}
		}
	}

	delete[] output_plain;
	return 0;
}



template int main_with_command_line<uint32_t>(
		program_params const&,
		char const*,
		void (*)(unsigned char const*, int, unsigned char const*, int, uint32_t*, int),
		void (*)(MpcVariable<unsigned char> const*, int, unsigned char const*, int, MpcVariable<uint32_t>*, int),
		void (*)(MpcVariableVerify<unsigned char> const*, int, unsigned char const*, int, MpcVariableVerify<uint32_t>*, int),
		int (*)(int, int));


template int main_with_command_line<uint64_t>(
		program_params const&,
		char const*, void (*)(unsigned char const*, int, unsigned char const*, int, uint64_t*, int),
		void (*)(MpcVariable<unsigned char> const*, int, unsigned char const*, int, MpcVariable<uint64_t>*, int),
		void (*)(MpcVariableVerify<unsigned char> const*, int, unsigned char const*, int, MpcVariableVerify<uint64_t>*, int),
		int (*)(int, int));

