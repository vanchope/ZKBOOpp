/*
 * time_utils.c
 *
 *  Created on: Aug 25, 2016
 *      Author: ivan
 */

#ifndef TIME_UTILS_C_
#define TIME_UTILS_C_

#include <time.h>

// measures clock() time and returns difference in milliseconds.
int measure(const clock_t* begin){
	clock_t delta = clock() - (*begin);
	return delta * 1000 / CLOCKS_PER_SEC;
}

#endif /* TIME_UTILS_C_ */
