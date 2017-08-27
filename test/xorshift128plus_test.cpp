/*
 * xorshift128plus_test.cpp
 *
 *  Created on: Oct 28, 2016
 *      Author: ivan
 */

#include "mpc_core.h"

#include "xorshift128plus.h"
#include "test_utility.h"
#include "assert.h"

int unittest(){
	return 0;
}


int main(int argc, char *argv[]){
	program_params params;
	memset(&params, 0, sizeof(program_params));
	params.outputlen_applicable = true;
	params.outputlen_bytes = 256/8;
	process_argv(params, argc, argv);

	assert ((params.outputlen_bytes & 15) == 0 && params.outputlen_bytes > 0);

	if (params.unit_test)
		return unittest();

	if (strlen(params.input) > 256/8){
		printf("In this test we expect input to be at most 32 bytes (256 bits). Received input's length = %ld\n",
				strlen(params.input));
		return 0;
	}

	int res = main_with_command_line<uint64_t>(params, "xorshift128+",
			xorshift128plus,
			xorshift128plus,
			xorshift128plus,
			xorshift128plus_random_tape_len_in_bytes);
	printf("\nFinished with return code %d.\n", res);
	return res;
}

