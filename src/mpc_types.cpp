/*
 * mpc_types.cpp
 *
 *  Created on: Nov 15, 2017
 *      Author: ivan
 */

#include "mpc_types.h"
#include <openssl/rand.h>
#include <sstream>

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

std::string format_memory(const char * data, int len){
	std::stringstream sstr;
	char buf[256];

	unsigned int split1, split2;
	if (len <= 100){
		split1 = len / 2;
		split2 = split1;
	}else{
		split1 = 32;
		split2 = len - 32;
	}

	for(unsigned int i=0; i<split1; i++){
		sprintf(buf, "%02x-", (uint8_t)data[i]);
		sstr << buf;
	}
	if (split1 != split2){
		sprintf(buf, "...(%d more)...", split2-split1);
		sstr << buf;
	}
	for(int i=split2; i<len; i++){
		sprintf(buf, "%02x-", (uint8_t)data[i]);
		sstr << buf;
	}
	return sstr.str();
}


void generate_random(unsigned char data[], int length_bytes){
	if(RAND_bytes((unsigned char *)data, length_bytes) != 1){
		printf("RAND_bytes failed, aborting\n");
		exit(EXIT_FAILURE);
	}
}

