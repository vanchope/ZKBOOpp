/*
 * Variable.h
 *
 *  Created on: Aug 31, 2016
 *      Author: ivan
 */

#ifndef INC_MPCVARIABLE_H_
#define INC_MPCVARIABLE_H_

#include "assert.h"
#include "stdint.h"
#include "string.h"
//#include "stdio.h"
#include <iostream>
#include <vector>

#include <openssl/rand.h>
#include <openssl/sha.h>

#include "mpc_types.h"

#define ZKBOO_RND_TAPE_SEED_LEN   16

struct MpcPartyView{
	unsigned char rnd_tape_seed[ZKBOO_RND_TAPE_SEED_LEN]; // used for generating a random tape
	std::vector<uint8_t> input;
	std::vector<uint32_t> output32; //filled in during the function execution in the mpc mode
	std::vector<uint64_t> output64; //filled in during the function execution in the mpc mode
};

//1 instance per iteration of ZKBoo per 1 party (out of three)
struct MpcPartyContext{
	MpcPartyView view;
	std::vector<uint32_t> randomness; // derived from rnd_tape_seed[16] //FIXME template?
	unsigned int randomnessUsed; //just a counter
	bool verify_mode;
	unsigned int verifier_counter32; // counter for output view
	unsigned int verifier_counter64; // counter for output view
	//unsigned char commitment[ZKBOO_COMMITMENT_VIEW_LENGTH];
};

struct MpcProof{
	MpcPartyView pView[2];
};

void InitMpcContext(MpcPartyContext *ctx, int randomTapeBytes, bool verify_mode);

void InitMpcContext(MpcPartyContext *ctx, const unsigned char keys[16], int randomTapeBytes, bool verify_mode);

void CommitMpcContext(unsigned char h[ZKBOO_COMMITMENT_VIEW_LENGTH] /*OUT*/, MpcPartyContext * mpcCtx /*IN*/);

void extract_es_from_Challenge(int * es /*OUT*/,
		const unsigned char hash[ZKBOO_HASH_BYTES] /*IN*/);



template <typename T> //uint32_t or uint64_t
class MpcVariable{
public:
	MpcVariable();

	template <typename U>
	MpcVariable(const MpcVariable<U> &that){
		memset(ctx, 0, sizeof(MpcPartyContext*) * 3);
		copy_from(that);
	}

	MpcVariable(const T &constant);
	MpcVariable(const T (&shares)[3], const MpcPartyContext *mpcCtx[3]);
	virtual ~MpcVariable();

	friend std::ostream& operator<< (std::ostream& stream, const MpcVariable<T>& mpcVar){
		stream << "[";
		for(int i=0; i<3; i++){
			if (i>0)
				stream << "; ";
			stream << mpcVar.val[i];
		}
		stream << " = " << (mpcVar.val[0] ^ mpcVar.val[1] ^ mpcVar.val[2]);
		stream << "]";
		return stream;
	}

	template <typename U>
	void operator=(const MpcVariable<U> &other){
		copy_from(other);
	}


	const MpcVariable operator~() const;
	MpcVariable& operator^=(const MpcVariable& that);
	MpcVariable& operator>>=(uint32_t n);
	MpcVariable& operator<<=(uint32_t n);
	MpcVariable& operator&=(const MpcVariable& that);
	MpcVariable& operator+=(const MpcVariable& that);
	MpcVariable& operator+=(const T &other);
	MpcVariable& operator|=(const MpcVariable &other);

	const MpcVariable operator^(const MpcVariable &that) const{
		return MpcVariable(*this) ^= that;
	}
	const MpcVariable operator>>(uint32_t n) const{
		return MpcVariable(*this) >>= n;
	}
	const MpcVariable operator<<(uint32_t n) const{
		return MpcVariable(*this) <<= n;
	}
	const MpcVariable operator&(const MpcVariable &that) const{
		return MpcVariable(*this) &= that;
	}
	const MpcVariable operator+(const MpcVariable &that) const{
		return MpcVariable(*this) += that;
	}
	const MpcVariable operator|(const MpcVariable &that) const{
		return MpcVariable(*this) |= that;
	}

	friend const MpcVariable<T> _rotateright(const MpcVariable<T> &that, int n){
		MpcVariable<T> res;
		for(int i=0; i<3; i++){
			res.val[i] = _rotateright(that.val[i], n);
		}
		res.copyCtx((const MpcPartyContext**)that.ctx);
		return res;
	}
	friend const MpcVariable<T> _rotateleft(const MpcVariable<T> &that, int n){
		MpcVariable<T> res;
		for(int i=0; i<3; i++){
			res.val[i] = _rotateleft(that.val[i], n);
		}
		res.copyCtx((const MpcPartyContext**)that.ctx);
		return res;
	}


	INLINE bool is_constant() const{
		return ctx[0] == 0;
	}

	uint32_t nextRandom32(int i); //FIXME next random64?

	T reconstruct() const;
	T value(int party) const{
		return val[party];
	}
	MpcPartyContext* const* ctx_() const{
		return ctx;
	}
private:
	T val[3];
	template <typename U>
	inline void copy_from(const MpcVariable<U> &that){
		for(int i=0; i<3; i++){
			val[i] = that.value(i);
		}
		copyCtx((const MpcPartyContext**)that.ctx_());
		//copyCtx(that.ctx_());
	}
	inline void copyCtx(const MpcPartyContext* mpcCtx[3]){
#ifdef INCLUDE_ASSERTS
		assert ((ctx[0] != 0 && ctx[1] != 0 && ctx[2] != 0) ||
				(ctx[0] == 0 && ctx[1] == 0 && ctx[2] == 0));
		assert ((mpcCtx[0] != 0 && mpcCtx[1] != 0 && mpcCtx[2] != 0) ||
				(mpcCtx[0] == 0 && mpcCtx[1] == 0 && mpcCtx[2] == 0));
#endif
		memcpy(ctx, mpcCtx, sizeof(MpcPartyContext*) * 3);
	}
	MpcPartyContext* ctx[3];
};


//
// The verify counter-part of the ZKBoo framework.
//
template <typename T> //uint32_t or uint64_t
class MpcVariableVerify{
public:
	MpcVariableVerify();

	// Copy constructor
	template <typename U>
	MpcVariableVerify(const MpcVariableVerify<U> &that): MpcVariableVerify(){
		copy_from(that);
	}

	MpcVariableVerify(const T &constant);
	MpcVariableVerify(const T (&shares)[2], const MpcPartyContext *mpcCtx[2]);
	MpcVariableVerify(const T (&shares)[2], const MpcPartyContext *mpcCtx[2], uint32_t fake_resp_randomness[]);
	virtual ~MpcVariableVerify();

	template <typename TF> friend std::ostream& operator<< (std::ostream& stream, const MpcVariableVerify<TF>& mpcVar);

	void operator=(const MpcVariableVerify &other);

	const MpcVariableVerify operator~() const;
	MpcVariableVerify& operator^=(const MpcVariableVerify& that);
	MpcVariableVerify& operator>>=(uint32_t n);
	MpcVariableVerify& operator<<=(uint32_t n);
	MpcVariableVerify& operator&=(const MpcVariableVerify& that);
	MpcVariableVerify& operator+=(const MpcVariableVerify& that);
	MpcVariableVerify& operator+=(const T &other);
	MpcVariableVerify& operator|=(const MpcVariableVerify& that);


	const MpcVariableVerify operator^(const MpcVariableVerify &that) const{
		return MpcVariableVerify(*this) ^= that;
	}
	const MpcVariableVerify operator>>(uint32_t n) const{
		return MpcVariableVerify(*this) >>= n;
	}
	const MpcVariableVerify operator<<(uint32_t n) const{
		return MpcVariableVerify(*this) <<= n;
	}
	const MpcVariableVerify operator&(const MpcVariableVerify &that) const{
		return MpcVariableVerify(*this) &= that;
	}
	const MpcVariableVerify operator+(const MpcVariableVerify &that) const{
		return MpcVariableVerify(*this) += that;
	}
	const MpcVariableVerify operator|(const MpcVariableVerify &that) const{
		return MpcVariableVerify(*this) |= that;
	}
	friend const MpcVariableVerify<T> _rotateright(const MpcVariableVerify<T> &that, int n){
		MpcVariableVerify<T> res;
		for(int i=0; i<2; i++){
			res.val[i] = _rotateright(that.val[i], n);
		}
		res.copy_ctx_from(that);
		return res;
	}
	friend const MpcVariableVerify<T> _rotateleft(const MpcVariableVerify<T> &that, int n){
		MpcVariableVerify<T> res;
		for(int i=0; i<2; i++){
			res.val[i] = _rotateleft(that.val[i], n);
		}
		res.copy_ctx_from(that);
		return res;
	}


	INLINE bool is_constant() const{
		return ctx[0] == 0;
	}

	uint32_t nextRandom32(int i);

	T value(int party) const{
		return val[party];
	}
	MpcPartyContext* const* ctx_() const{
		return ctx;
	}
private:
	T val[2];
	template <typename U>
	INLINE void copy_from(const MpcVariableVerify<U> &that){
		for(int i=0; i<2; i++){
			val[i] = that.value(i);
		}
		copy_ctx_from(that);
	}

	INLINE void copyCtxOnly(const MpcPartyContext* mpcCtx[]){
#ifdef INCLUDE_ASSERTS
		assert ((ctx[0] != 0 && ctx[1] != 0) ||
				(ctx[0] == 0 && ctx[1] == 0));
		assert ((mpcCtx[0] != 0 && mpcCtx[1] != 0) ||
				(mpcCtx[0] == 0 && mpcCtx[1] == 0));
#endif
		memcpy(&ctx, mpcCtx, sizeof(MpcPartyContext*) * 2);
	}

	template <typename U>
	INLINE void copy_ctx_from(const MpcVariableVerify<U> &that){
		copyCtxOnly((const MpcPartyContext**)that.ctx_());
		fake_resp_randomness = that.fake_resp_randomness;
		if (!is_constant() && !ctx[0]->verify_mode){
			assert (fake_resp_randomness != 0);
		}
	}
	MpcPartyContext* ctx[2];
public:
	uint32_t* fake_resp_randomness; // used only when ctx.verify_mode == false; [0] = counter
};


uint32_t nextRandom32_fromCtx(MpcPartyContext* ctx);


//std::string MpcPartyView_to_string(const MpcPartyView &mpcPartyView);
std::vector<std::string> MpcPartyView_to_string(const MpcPartyView &mpcPartyView);
//MpcPartyView string_to_MpcPartyView(const std::string &mpcPartyView_str);
MpcPartyView string_to_MpcPartyView(const std::string &mpcPartyView_part1_str, const std::string &mpcPartyView_part2_str);
std::string vectorstrings_to_string(const std::vector<std::string> &vs);
std::vector<std::string> string_to_vectorstrings(const std::string &str);


// helper functions
void GenChallengeROM_from_single_proof(unsigned char hash[ZKBOO_HASH_BYTES] /*OUT*/,
		const std::string &proof_commitment_full);


bool zkbpp_is_reconstruct_required(const MpcPartyContext* ctx[2]);

void getAllRandomness(
		const unsigned char key[16] /*IN*/,
		std::vector<uint32_t> &randomness /*OUT*/ /*space should be pre-allocated*/,
		int randomnessBits /*IN*/ /*expected to be multiple of 128*/);


#endif /* INC_MPCVARIABLE_H_ */

