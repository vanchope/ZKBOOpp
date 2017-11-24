/*
 * test_utility.h
 *
 *  Created on: Oct 27, 2016
 *      Author: ivan
 */

#ifndef INC_TEST_UTILITY_H_
#define INC_TEST_UTILITY_H_

#include "mpc_types.h"
#include "MpcVariable.h"
//#include "mpc_core.h"
//#include "zkbpp_core.h"

int LOG_LEVEL_ERROR = 0;
int LOG_LEVEL_INFO = 2;
int LOG_LEVEL_DEBUG = 4;

struct program_params{
	const char * algorithm; // [zkboo | zkbpp]

	bool outputlen_applicable;

	bool unit_test;

	bool run_prover;
	bool run_verifier;
	int repetitions;
	const char * input;
	int outputlen_bytes;
	int log_level;
};

bool process_argv(program_params & params, int argc, char * argv[]);

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
			int outputlen_bytes) );

#endif /* INC_TEST_UTILITY_H_ */
