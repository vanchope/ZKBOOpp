/*
 * chacha_test.cpp
 *
 *  Created on: Nov 25, 2016
 *      Author: ivan
 */
#include "mpc_core.h"

#include "chacha/chacha.h"
#include "test_utility.h"
#include "assert.h"

int unittest(){
	return 0;
}

int main(int argc, char *argv[]){
	program_params params;
	memset(&params, 0, sizeof(program_params));
	params.outputlen_applicable = true;
	params.outputlen_bytes = 32; // or default 16?
	process_argv(params, argc, argv);

	if (params.unit_test)
		return unittest();

	if (strlen(params.input)>32){
		printf("In this test we expect input to be at most 32 bytes (256 bits). Received input's length = %ld\n",
				strlen(params.input));
		return 0;
	}

	//TODO requires some additional work to instantiate with three types T8, T32, and T64.

//	int res = main_with_command_line<uint32_t>(params, "chacha",
//			chacha,
//			chacha,
//			chacha,
//			chacha_random_tape_len_in_bytes);
//	printf("\nFinished with return code %d.\n", res);
//	return res;
	printf("not yet implemented\n");
	return 1;
}
