/*
 * Matrix.h
 *
 * 2D dynamic array via 1D contiguous memory region.
 *
 *  Created on: May 19, 2017
 *      Author: ivan
 */

#ifndef INC_MATRIX_H_
#define INC_MATRIX_H_

#include "mpc_types.h" // for INLINE
#include <cstring> // for memset
#include <assert.h>

namespace mpc {

template <typename T>
class Matrix2D {
public:
	Matrix2D(unsigned long int size1, unsigned long int size2){
		size1_ = size1;
		size2_ = size2;
		assert(size1 * size2 < 2000000000);
		data = new T[size1 * size2];
		memset(data, 0, size1_ * size2_ * sizeof(T));
	}
	~Matrix2D(){ delete[] data; }
	INLINE unsigned long int index(int x, int y) const {return x * size2_ + y;}
	unsigned long int size_bytes(){ return size1_ * size2_; }
private:
	unsigned long int size1_;
	unsigned long int size2_;
public:
	T* data;
};



template <typename T>
class Matrix3D {
public:
	Matrix3D(unsigned long int size1, unsigned long int size2, unsigned long int size3){
		size1_ = size1;
		size2_ = size2;
		size3_ = size3;
		size23_ = size2_ * size3_;
		assert(((long long)size1) * size2 * size3 < 2000000000L);
		data = new T[size1_ * size23_];
		memset(data, 0, size1_ * size23_ *  sizeof(T));
	}
	~Matrix3D(){ delete[] data; }
	INLINE unsigned long int index(int x, int y, int z) const {return x * size23_ + y * size3_ + z;}
	unsigned long int size_bytes(){ return size1_ * size23_ * sizeof(T); }
	unsigned long int number_of_elements(){ return size1_ * size23_; }
private:
	unsigned long int size1_;
	unsigned long int size2_;
	unsigned long int size3_;
	unsigned long int size23_;
public:
	T* data;
};

} /* namespace mpc */

#endif /* INC_MATRIX_H_ */
