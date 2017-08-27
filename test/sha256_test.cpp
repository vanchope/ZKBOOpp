/*
 * sha256_test.cpp
 *
 *  Created on: Aug 31, 2016
 *      Author: ivan
 */


#include "string.h"
#include "stdio.h"
#include <string>
#include <iostream>

#include "mpc_core.h"
#include "sha256.h"

#include "test_utility.h"

using namespace std;


void testSHA256_for_message(const char * msg){
	uint8_t * input = (uint8_t * ) msg;
	uint32_t res[8]; // 256 bits
	memset(res, 0, 8 * sizeof(uint32_t));

	sha256<uint8_t, uint32_t>(input, strlen(msg), NULL, 0, res, 8);

	debug_func("normal_SHA256", msg, strlen(msg), NULL, 0, res, 8);

	printf("rewritten differently, normal_SHA256('%s')=", msg);
	for(int i=0; i<8; i++){
		printf("%X ", res[i]);
	}
	printf("\n");
}


void sha256_unit_test(){
	printf("Sha256 algorithm. Running unit test..\n");

	const char* sha_input[] = {"", "1", "12345678", "abc"};
	int test_number = sizeof(sha_input)/sizeof(sha_input[0]);

	for(int i=0; i<test_number; i++){
		testSHA256_for_message(sha_input[i]);
	}
	// Expected SHA256('')=E3B0C442 98FC1C14 9AFBF4C8 996FB924 27AE41E4 649B934C A495991B 7852B855
}


int main(int argc, char *argv[]){
	program_params params;
	memset(&params, 0, sizeof(program_params));
	params.outputlen_applicable = false;
	params.outputlen_bytes = 256/8;
	process_argv(params, argc, argv);
	if (params.unit_test){
		sha256_unit_test();
		return 0;
	}
	int res = main_with_command_line<uint32_t>(params, "sha256",
			sha256,
			sha256,
			sha256,
			sha256_random_tape_len_in_bytes);
	printf("\nFinished with return code %d.\n", res);
	return res;
}


