/*
 * MpcCore_test.cpp
 *
 *  Created on: Oct 7, 2016
 *      Author: ivan
 */

#include "sha256.h"
#include "string.h"
#include "stdio.h"
#include <iostream>
#include "mpc_core.h"


using namespace std;


// Test more simple functions
template <typename T8, typename T32>
void foo(const T8 &a,const T8 &b, T32& res){
//	res = a ^ b;
//	res = _rotr(res, 1);
//	res = _rotl(res, 2);
//	res >>= 1;
//	res = ~res;
//	res = res & a;
	res = (T32) a + (T32) b;
}

template void foo<uint8_t, uint32_t>(const uint8_t &a,const uint8_t &b, uint32_t& res);
template void foo< MpcVariable<uint8_t>, MpcVariable<uint32_t> >(
		const MpcVariable<uint8_t> &a,
		const MpcVariable<uint8_t> &b,
		MpcVariable<uint32_t>& res);

int main(){
	uint32_t a0 = 255;
	uint32_t b0 = 7;
	{
		uint32_t a = a0;
		uint32_t b = b0;
		uint32_t res;

		foo<uint32_t>(a, b, res);
		cout << "res (uint32_t) = " << res << endl;
	}

	{
		int random_tape_bytes = 100;
		MpcPartyContext mpcCtxArray[3];
		MpcPartyContext* mpcCtx[3];
		for(int i=0; i<3; i++){
			mpcCtx[i] = &mpcCtxArray[i];
			InitMpcContext(mpcCtx[i], random_tape_bytes, false);
		}

		MpcVariable<uint8_t> a;
		//convert_input(a, a0, (const MpcPartyContext**) mpcCtx);
		convert_input(a, a0, (const MpcPartyContext **) mpcCtx);
		MpcVariable<uint32_t> b(b0);
		MpcVariable<uint32_t> res;
		foo<MpcVariable<uint32_t> >(a, b, res);

		cout << "res (MpcVariable) = " << res << endl;
		cout << "reconstruct res (MpcVariable) = " << res.reconstruct() << endl;
	}

}

