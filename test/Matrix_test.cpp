/*
 * Matrix_test.cpp
 *
 *  Created on: May 19, 2017
 *      Author: ivan
 */

#include "Matrix.h"
#include <iostream>
#include <stdio.h>

using namespace mpc;
using namespace std;

int main(){
	int val=0;
	Matrix2D<int> a(3, 5);
	for(int i=0; i< 3*5; i++){
		a.data[i] = i;
	}
	for(int i=0; i<3; i++){
		for(int j=0; j<5; j++){
			printf("a[%d][%d] = %d\n", i,j, a.data[a.index(i, j)]);
			assert(a.data[a.index(i, j)] == val++);
		}
	}

	val=0;
	Matrix3D<int> b(3, 2, 5);
	for(unsigned int i=0; i< b.size_bytes(); i++){
		b.data[i] = i;
	}
	for(int i=0; i<3; i++){
		for(int j=0; j<2; j++){
			for(int k=0; k<5; k++){
				printf("a[%d][%d][%d] = %d\n", i,j,k, b.data[b.index(i, j, k)]);
				assert(b.data[b.index(i, j, k)] == val++);
			}
		}
	}

	printf("Finished.\n");
}
