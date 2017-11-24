/*
 * MpcVariable.cpp
 *
 *  Created on: Aug 31, 2016
 *      Author: ivan
 */

#include "MpcVariable.h"

#include "assert.h"
#include <iostream>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <sstream>


template <typename T>
MpcVariable<T>::MpcVariable(){
	memset(ctx, 0, sizeof(MpcPartyContext*) * 3);
}

template <typename T>
MpcVariableVerify<T>::MpcVariableVerify(){
	memset(ctx, 0, sizeof(MpcPartyContext*) * 2);
	fake_resp_randomness = nullptr;
}

template <typename T>
void MpcVariableVerify<T>::operator=(const MpcVariableVerify &other){
	copy_from(other);
}

template <typename T>
MpcVariable<T>::MpcVariable(const T &constant) : MpcVariable<T>::MpcVariable(){
	for(int i=0; i<3; i++){
		val[i] = constant;
	}
}

template <typename T>
MpcVariableVerify<T>::MpcVariableVerify(const T &constant) : MpcVariableVerify<T>::MpcVariableVerify(){
	for(int i=0; i<2; i++){
		val[i] = constant;
	}
}

template <typename T>
MpcVariable<T>::MpcVariable(const T (&shares)[3], const MpcPartyContext *mpcCtx[3]) : MpcVariable<T>::MpcVariable(){
	for(int i=0; i<3; i++){
		val[i] = shares[i];
	}
	copyCtx(mpcCtx);
}

template <typename T>
MpcVariableVerify<T>::MpcVariableVerify(const T (&shares)[2], const MpcPartyContext *mpcCtx[2])
		: MpcVariableVerify<T>::MpcVariableVerify(){
	for(int i=0; i<2; i++){
		val[i] = shares[i];
	}
	copyCtxOnly(mpcCtx);
}

template <typename T>
MpcVariableVerify<T>::MpcVariableVerify(const T (&shares)[2], const MpcPartyContext *mpcCtx[2],
		uint32_t fake_resp_randomness[]) : MpcVariableVerify<T>::MpcVariableVerify(shares, mpcCtx){
	this->fake_resp_randomness = fake_resp_randomness;
}

template <typename T>
MpcVariable<T>::~MpcVariable(){
	//ctx = NULL; //context should be released manually outside the MpcVariable class
}

template <typename T>
MpcVariableVerify<T>::~MpcVariableVerify(){
}

template <typename T>
T MpcVariable<T>::reconstruct() const{
	return val[0] ^ val[1] ^ val[2];
}

template <typename T>
MpcVariable<T>& MpcVariable<T>::operator^=(const MpcVariable& other){
	if (is_constant()){
		copyCtx((const MpcPartyContext**)other.ctx);
	}
	for(int i=0; i<3; i++){
		this->val[i] ^= other.val[i];
	}
	return *this;
}

template <typename T>
MpcVariableVerify<T>& MpcVariableVerify<T>::operator^=(const MpcVariableVerify& other){
	if (is_constant()){
		copy_ctx_from(other);
	}
	for(int i=0; i<2; i++){
		this->val[i] ^= other.val[i];
	}
	return *this;
}

template <typename T>
MpcVariable<T>& MpcVariable<T>::operator>>=(uint32_t n){
	for(int i=0; i<3; i++){
		this->val[i] >>= n;
	}
	return *this;
}

template <typename T>
MpcVariableVerify<T>& MpcVariableVerify<T>::operator>>=(uint32_t n){
	for(int i=0; i<2; i++){
		this->val[i] >>= n;
	}
	return *this;
}

template <typename T>
MpcVariable<T>& MpcVariable<T>::operator<<=(uint32_t n){
	for(int i=0; i<3; i++){
		this->val[i] <<= n;
	}
	return *this;
}

template <typename T>
MpcVariableVerify<T>& MpcVariableVerify<T>::operator<<=(uint32_t n){
	for(int i=0; i<2; i++){
		this->val[i] <<= n;
	}
	return *this;
}


template <typename T>
const MpcVariable<T> MpcVariable<T>::operator~() const{
	MpcVariable res;
	for(int i=0; i<3; i++){
		res.val[i] = ~(this->val[i]);
	}
	res.copyCtx((const MpcPartyContext**)ctx);
	return res;
}

template <typename T>
const MpcVariableVerify<T> MpcVariableVerify<T>::operator~() const{
	MpcVariableVerify res;
	for(int i=0; i<2; i++){
		res.val[i] = ~(this->val[i]);
	}
	res.copy_ctx_from(*this);
	return res;
}

//template <typename T>
uint32_t nextRandom32_fromCtx(MpcPartyContext* ctx){
	if (ctx->randomness.size()<= ctx->randomnessUsed){
		std::stringstream sstr;
		sstr << "not enough randomness pre-generated : " << ctx->randomness.size() * 4 << " bytes"<< std::endl;
		throw std::runtime_error(sstr.str());
	}
	uint32_t res = ctx->randomness[ctx->randomnessUsed];
	ctx->randomnessUsed++;
	return res;
}


template <typename T>
uint32_t MpcVariable<T>::nextRandom32(int i /* 0 to 2 */){
	return nextRandom32_fromCtx(ctx[i]);
}

template <typename T>
uint32_t MpcVariableVerify<T>::nextRandom32(int i /* 0 to 1; 2 is used for fake randomness in the non-verify mode */){
	if (i<2)
		return nextRandom32_fromCtx(ctx[i]);
	return 0;
}

// AND
template <typename T>
MpcVariable<T>& MpcVariable<T>::operator&=(const MpcVariable& that){
	if (is_constant() && that.is_constant()){
		for(int i=0; i<3; i++)
			val[i] &= that.val[i];
		return *this;
	}
	if (is_constant()){
		copyCtx((const MpcPartyContext**)that.ctx);
	}
	assert (ctx[0] != NULL);
	T r[3];
	for(int i=0; i<3; i++){
		r[i] = nextRandom32(i); //FIXME 64 bit
	}

	T t[3];
	for(int i=0; i<3; i++){
		t[i] =    (val[i]       & that.val[(i+1)%3])
				^ (val[(i+1)%3] & that.val[i])
				^ (val[i]       & that.val[i])
				^ r[i]
				^ r[(i+1)%3];
	}

	for(int i=0; i<3; i++){
		val[i] = t[i];
	}


	for(int i=0; i<3; i++){
		if (sizeof(T) == 4){
			ctx[i]->view.output32.push_back(val[i]);
		}else if (sizeof(T) == 8){
			ctx[i]->view.output64.push_back(val[i]);
		}else{
			throw std::runtime_error("not supported");
		}
	}
	return *this;
}

template <typename T>
MpcVariableVerify<T>& MpcVariableVerify<T>::operator&=(const MpcVariableVerify& that){
	if (is_constant() && that.is_constant()){
		for(int i=0; i<2; i++)
			val[i] &= that.val[i];
		return *this;
	}
	if (is_constant()){
		copy_ctx_from(that);
	}
	assert (ctx[0] != NULL);
	T r[2];
	for(int i=0; i<2; i++){
		r[i] = nextRandom32(i);
	}

	T t =      (val[0] & that.val[1])
			 ^ (val[1] & that.val[0])
			 ^ (val[0] & that.val[0])
			 ^ r[0] ^ r[1];

	if (!ctx[0]->verify_mode){
		val[0] = t;
		val[1] = fake_resp_randomness[fake_resp_randomness[0]++];
		for(int i=0; i<2; i++){
			if (sizeof(T) == 4){
				ctx[i]->view.output32.push_back(val[i]);
			}else if (sizeof(T) == 8){
				ctx[i]->view.output64.push_back(val[i]);
			}else{
				throw std::runtime_error("not supported");
			}
		}
	}else{
//		bool reconstruct_required = ctx[0]->view.output32.size() != ctx[1]->view.output32.size()
//				|| ctx[0]->view.output64.size() == ctx[1]->view.output64.size();
		bool reconstruct_required = zkbpp_is_reconstruct_required((const MpcPartyContext**)ctx);

		if (sizeof(T)==4){
			if (!reconstruct_required){
				if (t != ctx[0]->view.output32[ctx[0]->verifier_counter32]){
					throw std::runtime_error("verification &= failed");
				}
			}else{ //zkbpp, Opt.6
				ctx[0]->view.output32.push_back(t);
			}


			val[0] = t;
			val[1] = ctx[1]->view.output32[ctx[1]->verifier_counter32];
			for(int i=0; i<2; i++){
				ctx[i]->verifier_counter32 += 1;
			}
		}else if (sizeof(T)==8){
			if (!reconstruct_required){
				if (t != ctx[0]->view.output64[ctx[0]->verifier_counter64]){
					throw std::runtime_error("verification &= failed");
				}
			}else{ //zkbpp, Opt.6
				ctx[0]->view.output64.push_back(t);
			}

			val[0] = t;
			val[1] = ctx[1]->view.output64[ctx[1]->verifier_counter64];
			for(int i=0; i<2; i++){
				ctx[i]->verifier_counter64 += 1;
			}
		}else{
			throw std::runtime_error("not supported");
		}
	}
	return *this;
}

// ADD
template <typename T>
MpcVariable<T>& MpcVariable<T>::operator+=(const MpcVariable& that){
	if (is_constant() && that.is_constant()){
		for(int i=0; i<3; i++)
			val[i] += that.val[i];
		return *this;
	}

#ifdef INCLUDE_ASSERTS
	//DEBUG
	T before = reconstruct();
#endif

	if (is_constant()){
		copyCtx((const MpcPartyContext**)that.ctx);
	}
	assert (ctx[0] != NULL && ctx[1] != NULL);
	T r[3];
	for(int i=0; i<3; i++)
		r[i] = nextRandom32(i);

	T c[3] = { 0 };
	uint8_t a[3], b[3];
	uint8_t t;
	for(unsigned int i=0; i< 8 * sizeof(T)-1; i++){
		for(int j=0; j<3; j++){
			a[j]=GETBIT(     val[j]^c[j], i);
			b[j]=GETBIT(that.val[j]^c[j], i);
		}
		for(int j=0; j<3; j++){
			t = (a[j]&b[(j+1) % 3]) ^ (a[(j+1)%3]&b[j]) ^ GETBIT(r[(j+1)%3], i);
			SETBIT(c[j], i+1, t ^ (a[j]&b[j]) ^ GETBIT(c[j],i) ^ GETBIT(r[j],i), T);
		}
	}
	for(int j=0; j<3; j++){
		val[j] = val[j] ^ that.val[j] ^ c[j];
	}
	for(int j=0; j<3; j++){
		if (sizeof(T)==4){
			ctx[j]->view.output32.push_back(c[j]);
		}else if (sizeof(T)==8){
			ctx[j]->view.output64.push_back(c[j]);
		}else{
			throw std::runtime_error("not supported");
		}
	}

#ifdef INCLUDE_ASSERTS
	T add = that.reconstruct();
	T after = reconstruct();
	if (before + add != after){
		assert(before + add == after);
	}
#endif

	return *this;
}

template <typename T>
MpcVariableVerify<T>& MpcVariableVerify<T>::operator+=(const MpcVariableVerify& that){
	if (is_constant() && that.is_constant()){
		for(int i=0; i<2; i++)
			val[i] += that.val[i];
		return *this;
	}
	if (is_constant())
		copy_ctx_from(that);
	assert (ctx[0] != NULL);
	T r[2];
	for(int i=0; i<2; i++)
		r[i] = nextRandom32(i);

	T c[2] = {0};
	uint8_t a[2], b[2];
	uint8_t t;
	if (!ctx[0]->verify_mode){
		c[1] = fake_resp_randomness[fake_resp_randomness[0]++]; // FIXME 64 bit;
		SETBIT(c[1], 0, 0, T); //bit 0 should be always 0

		for(unsigned int i=0; i<8*sizeof(T)-1; i++){
			for(int j=0; j<2; j++){
				a[j]=GETBIT(     val[j]^c[j], i);
				b[j]=GETBIT(that.val[j]^c[j], i);
			}
			t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
			SETBIT(c[0], i+1, (t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i)), T);
		}

		for(int j=0; j<2; j++){
			val[j] = val[j] ^ that.val[j] ^ c[j];
		}

		for(int j=0; j<2; j++){
			if (sizeof(T)==4){
				ctx[j]->view.output32.push_back(c[j]);
			}else if (sizeof(T)==8){
				ctx[j]->view.output64.push_back(c[j]);
			}else{
				throw std::runtime_error("not supported");
			}
		}
	}else{  // verify mode
//		bool reconstruct_required = ctx[0]->view.output32.size() != ctx[1]->view.output32.size()
//				|| ctx[0]->view.output64.size() == ctx[1]->view.output64.size();
		bool reconstruct_required = zkbpp_is_reconstruct_required((const MpcPartyContext**)ctx);

		for(int j=0; j<2; j++){
			if (sizeof(T)==4){
				if (!reconstruct_required || j!=0){
					c[j] = ctx[j]->view.output32[ctx[j]->verifier_counter32];
				}
				ctx[j]->verifier_counter32 += 1;
			}else if (sizeof(T)==8){
				if (!reconstruct_required || j!=0){
					c[j] = ctx[j]->view.output64[ctx[j]->verifier_counter64];
				}
				ctx[j]->verifier_counter64 += 1;
			}else{
				throw std::runtime_error("not supported");
			}
		}
		for(unsigned int i=0; i<8*sizeof(T)-1; i++){
			for(int j=0; j<2; j++){
				a[j]=GETBIT(     val[j]^c[j], i);
				b[j]=GETBIT(that.val[j]^c[j], i);
			}
			t = (a[0]&b[1]) ^ (a[1]&b[0]) ^ GETBIT(r[1],i);
			if (!reconstruct_required){ //zkboo
				if(GETBIT(c[0],i+1) != (t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i))) {
					throw std::runtime_error("verification += failed");
				}
			}else{ //zkbpp, Opt.6
				SETBIT(c[0],i+1, t ^ (a[0]&b[0]) ^ GETBIT(c[0],i) ^ GETBIT(r[0],i), T);
			}
		}

		if (reconstruct_required){
			if (sizeof(T)==4){
				ctx[0]->view.output32.push_back(c[0]);
			}else if (sizeof(T)==8){
				ctx[0]->view.output64.push_back(c[0]);
			}else{
				throw std::runtime_error("not supported");
			}
		}

		for(int j=0; j<2; j++){
			val[j] = val[j] ^ that.val[j] ^ c[j];
		}
	}
	return *this;
}

template <typename T>
MpcVariable<T>& MpcVariable<T>::operator+=(const T &other){
	return operator +=(MpcVariable(other));
}

template <typename T>
MpcVariableVerify<T>& MpcVariableVerify<T>::operator+=(const T &other){
	return operator +=(MpcVariableVerify(other));
}

template <typename T>
MpcVariable<T>& MpcVariable<T>::operator|=(const MpcVariable& other){
	// This operator is used only in "rotate" operator. Otherwise it won't work properly.
	if (is_constant()){
		copyCtx((const MpcPartyContext**)other.ctx);
	}
	for(int i=0; i<3; i++){
		this->val[i] |= other.val[i];
	}
	return *this;
}

template <typename T>
MpcVariableVerify<T>& MpcVariableVerify<T>::operator|=(const MpcVariableVerify& other){
	if (is_constant()){
		copy_ctx_from(other);
	}
	for(int i=0; i<2; i++){
		this->val[i] |= other.val[i];
	}
	return *this;
}




// --------------------------------------------------
//  OpenSSL stuff
// --------------------------------------------------
void handleErrors(void) {
	ERR_print_errors_fp(stderr);
	abort();
}

void setupAES(EVP_CIPHER_CTX *ctx, const unsigned char key[16]) {
	EVP_CIPHER_CTX_init(ctx);

	///* A 128 bit key */
	//unsigned char *key = (unsigned char *)"01234567890123456";

	/* A 128 bit IV */
	unsigned char *iv = (unsigned char *)"01234567890123456";

	/* Create and initialise the context */
	//if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

	/* Initialise the encryption operation. IMPORTANT - ensure you use a key
	 * and IV size appropriate for your cipher
	 * In this example we are using 256 bit AES (i.e. a 256 bit key). The
	 * IV size for *most* modes is the same as the block size. For AES this
	 * is 128 bits */
	if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
		handleErrors();
}
// required size for randomness[]
void getAllRandomness(
		const unsigned char key[16] /*IN*/,
		std::vector<uint32_t> &randomness /*OUT*/ /*space should be pre-allocated*/,
		int randomnessBits /*IN*/ /*expected to be multiple of 128*/) {
	//"SHA-256"
	//Generate randomness: We use 728*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 728*32/128 = 182 iterations

	//"SHA-1"
	//Generate randomness: We use 365*32 bit of randomness per key.
	//Since AES block size is 128 bit, we need to run 365*32/128 = 91.25 iterations. Let's just round up.

	EVP_CIPHER_CTX ctx;
	setupAES(&ctx, key);
	unsigned char *plaintext =
			(unsigned char *)"0000000000000000";
	int out_len;
	uint32_t buf[4];
	for(int j=0; j<randomnessBits/128; j++) {
		//encrypt by blocks of 128 bits
		if(1 != EVP_EncryptUpdate(&ctx, (unsigned char *)buf, &out_len,
					plaintext, strlen ((char *)plaintext)))
			handleErrors();

		for(int i=0; i<4; i++)
			randomness.push_back(buf[i]);
	}
	EVP_CIPHER_CTX_cleanup(&ctx);
}

// generates random tape based on keys
//template <typename T>
void InitMpcContext(MpcPartyContext *ctx, const unsigned char keys[16], int randomTapeBytes, bool verify_mode){
	memcpy(ctx->view.rnd_tape_seed, keys, 16);
	ctx->randomnessUsed = 0;
	getAllRandomness(ctx->view.rnd_tape_seed, ctx->randomness, randomTapeBytes * 8);
	ctx->verifier_counter32 = 0;
	ctx->verifier_counter64 = 0;
	ctx->verify_mode = verify_mode;
}

// generates random keys
//template <typename T>
void InitMpcContext(MpcPartyContext *ctx, int randomTapeBytes, bool verify_mode){
	generate_random(ctx->view.rnd_tape_seed, 16);
	InitMpcContext(ctx, ctx->view.rnd_tape_seed, randomTapeBytes, verify_mode);
}

// commit keys and view
void CommitMpcContext(unsigned char h[ZKBOO_COMMITMENT_VIEW_LENGTH] /*OUT*/, MpcPartyContext* mpcCtx /*IN*/){
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &(mpcCtx->view.rnd_tape_seed), 16);
	// second parameter is a pointer to an array of uint32_t numbers
	SHA256_Update(&ctx, &(mpcCtx->view.output32[0]), sizeof(uint32_t) * mpcCtx->view.output32.size());
	SHA256_Update(&ctx, &(mpcCtx->view.output64[0]), sizeof(uint64_t) * mpcCtx->view.output64.size());
	SHA256_Final(h, &ctx);
}



void extract_es_from_Challenge(int * es /*OUT, elements are 0,1,or 2*/,
		const unsigned char hash[ZKBOO_HASH_BYTES] /*IN*/){

	// We do it in base 3. For 136 rounds we need 216<256 bits.
	// Blocks = 8.  Bits requires 27,  bits block 32, rounds 17

	// Lets split into 8 blocks of size 32 bits, each such a block encodes 17 rounds
	int ir = 0;
	for(int i=0; i<8; i++){
		uint32_t number = *(hash + 4*i);
		// Only 27 out of 32 least significant bits are used to encode 17 rounds.
		// Only 29 out of 32 least significant bits are used to encode 18 rounds.
		for(int j=0; j<18; j++){
			es[ir++] = number % 3; // 0,1,or 2
			number /= 3;
			if (ir>=ZKBOO_NUMBER_OF_ROUNDS){
				return;
			}
		}
	}
	throw std::runtime_error("too many rounds: cannot extract the challenge\n");

	/*  original code
	//SHA256 generated 32bytes of output, i.e. 256 bits.
	//It is 128 pairs of bits, which is smaller than NUMBER_OF_ROUNDS = 136 for 2^{-80}.

	//Pick bits from hash
	int i = 0;
	int bitTracker = 0;
	while(i < NUMBER_OF_ROUNDS) {
		if(bitTracker >= SHA256_DIGEST_LENGTH*8) {
			//Generate new hash as we have run out of bits in the previous hash
			SHA256_Init(&ctx);
			SHA256_Update(&ctx, hash, sizeof(hash));
			SHA256_Final(hash, &ctx);
			bitTracker = 0;
		}

		int b1 = GETBIT(hash[bitTracker/8], bitTracker % 8);
		int b2 = GETBIT(hash[(bitTracker+1)/8], (bitTracker+1) % 8);
		if(b1 == 0) {
			if(b2 == 0) {
				es[i] = 0;
			} else {
				es[i] = 1;
			}
			i++;
		} else {
			if(b2 == 0) {
				es[i] = 2;
				i++;
			}
		}
		bitTracker += 2;
	}
	*/
}


template <class T>
std::ostream& operator << (std::ostream& os, const std::vector<T>& v){
    os << "[";
    for (typename std::vector<T>::const_iterator it = v.begin(); it != v.end(); it++){
        os << " " << (uint64_t) *it;
    }
    os << "]";
    return os;
}

void dump_MpcPartyView(const MpcPartyView &mpcPartyView){
	using namespace std;
	cout << "dump MpcPartyView: " << endl;
	cout << "rand" << mpcPartyView.rnd_tape_seed << endl;
	cout << "input" << mpcPartyView.input << endl;
	cout << "output32[" << mpcPartyView.output32.size() << "]" << mpcPartyView.output32 << endl;
	cout << "output64[" << mpcPartyView.output64.size() << "]" << mpcPartyView.output64 << endl;
}


// return type is string to make it compatible with python
//
// layout is the following: two strings
//  1. [16:random seed] [4:len_input_bytes] [4:len_output_bytes] [4:len_output64_bytes]   # header part
// 	   [input]              # data input part
//  2. [output] [output64]   # data output part
std::vector<std::string> MpcPartyView_to_string(const MpcPartyView &mpcPartyView){
	std::vector<std::string> res;

	//dump_MpcPartyView(mpcPartyView);

	//part 1
	{	// [16:rnd_seed][4:inplen][:input]
		int total_len_part1 = 0;
		total_len_part1 += sizeof(mpcPartyView.rnd_tape_seed); //randomness part


		uint32_t input_size_bytes = mpcPartyView.input.size() * sizeof(uint8_t);
		total_len_part1 += input_size_bytes;
		total_len_part1 += sizeof(uint32_t); // encode length

		char * data_part1 = new char[total_len_part1];
		int offset_part1 = 0;
		memcpy(data_part1 + offset_part1, mpcPartyView.rnd_tape_seed, sizeof(mpcPartyView.rnd_tape_seed));
		offset_part1 += sizeof(mpcPartyView.rnd_tape_seed);

		*(uint32_t*)(data_part1 + offset_part1) = input_size_bytes;
		offset_part1 += sizeof(uint32_t);

		memcpy(&data_part1[offset_part1], &(mpcPartyView.input[0]), input_size_bytes);
		offset_part1 += input_size_bytes;
		res.push_back(std::string(data_part1, total_len_part1));
		delete[] data_part1;
	}


	// part 2
	{   //[4:size32][4:size64][:out32][:out64]
		int total_len_part2 = 0;

		uint32_t output32_size_bytes = mpcPartyView.output32.size() * sizeof(uint32_t);
		total_len_part2 += sizeof(uint32_t); // encode length
		total_len_part2 += output32_size_bytes;

		uint32_t output64_size_bytes = mpcPartyView.output64.size() * sizeof(uint64_t);
		total_len_part2 += sizeof(uint32_t); // encode length
		total_len_part2 += output64_size_bytes;

		char * data_part2 = new char[total_len_part2];
		int offset_part2 = 0;

		*(uint32_t*)(data_part2 + offset_part2) = mpcPartyView.output32.size();
		offset_part2 += sizeof(uint32_t);

		*(uint32_t*)(data_part2 + offset_part2) = mpcPartyView.output64.size();
		offset_part2 += sizeof(uint32_t);

		memcpy(&data_part2[offset_part2], &(mpcPartyView.output32[0]), output32_size_bytes);
		offset_part2 += output32_size_bytes;

		memcpy(&data_part2[offset_part2], &(mpcPartyView.output64[0]), output64_size_bytes);
		offset_part2 += output64_size_bytes;

		assert(offset_part2 == total_len_part2);
		res.push_back(std::string(data_part2, total_len_part2));
		delete[] data_part2;
	}
	return res;
}


MpcPartyView string_to_MpcPartyView(const std::string &mpcPartyView_part1_str, const std::string &mpcPartyView_part2_str){
	MpcPartyView mpcPartyView;
	//part 1
	{
		const char * raw_data_part1_ptr = &(mpcPartyView_part1_str.data()[0]);
		uint32_t offset_part1 = 0;

		uint32_t rnd_size = sizeof(mpcPartyView.rnd_tape_seed);
		memcpy(mpcPartyView.rnd_tape_seed, raw_data_part1_ptr + offset_part1, rnd_size);
		offset_part1 += rnd_size;

		uint32_t* input_size = (uint32_t*) (raw_data_part1_ptr + offset_part1);
		offset_part1 += sizeof(uint32_t);

		uint8_t * input_ptr = (uint8_t*) (raw_data_part1_ptr + offset_part1);
		mpcPartyView.input.assign(input_ptr, input_ptr + (*input_size));
		offset_part1 += (*input_size) * sizeof(uint8_t);
		assert(offset_part1 == mpcPartyView_part1_str.size());
	}

	// part 2
	if (mpcPartyView_part2_str.length()>0) {
		const char * raw_data_part2_ptr = &(mpcPartyView_part2_str.data()[0]);
		uint32_t offset_part2 = 0;

		uint32_t* output32_size = (uint32_t*) (raw_data_part2_ptr + offset_part2);
		offset_part2 += sizeof(uint32_t);

		uint32_t* output64_size = (uint32_t*) (raw_data_part2_ptr + offset_part2);
		offset_part2 += sizeof(uint32_t);


		uint32_t * output32_ptr = (uint32_t*) (raw_data_part2_ptr + offset_part2);
		mpcPartyView.output32.assign(output32_ptr, output32_ptr+(*output32_size));
		offset_part2 += (*output32_size) * sizeof(uint32_t);

		uint64_t * output64_ptr = (uint64_t*) (raw_data_part2_ptr + offset_part2);
		mpcPartyView.output64.assign(output64_ptr, output64_ptr+(*output64_size));
		offset_part2 += (*output64_size) * sizeof(uint64_t);

		assert(offset_part2 == mpcPartyView_part2_str.size());
	}

	//dump_MpcPartyView(mpcPartyView);
	return mpcPartyView;
}


// the output string is in the following format:
// {[4 bytes size] [string]} {...} ...
std::string vectorstrings_to_string(const std::vector<std::string> &vs){
	int total_size = 0;
	for(size_t i=0; i<vs.size(); i++){
		total_size += sizeof(uint32_t) + vs[i].size(); // size + content
	}
	char * data = new char[total_size];
	int offset = 0;
	for(size_t i=0; i<vs.size(); i++){
		*(uint32_t*)(&data[offset]) = (uint32_t) vs[i].size();
		offset += sizeof(uint32_t);
		memcpy(&data[offset], &(vs[i][0]), vs[i].size());
		offset += vs[i].size();
	}
	assert(offset == total_size);
	std::string res = std::string(data, total_size);
	delete[] data;
	return res;
}


std::vector<std::string> string_to_vectorstrings(const std::string &str){
	std::vector<std::string> v;
	uint32_t offset = 0;
	while(offset < str.size()){
		uint32_t* str_size_ptr = (uint32_t*)(str.data() + offset);
		std::string s(str, offset+sizeof(uint32_t), *str_size_ptr);
		offset += sizeof(uint32_t) + *str_size_ptr;
		v.push_back(s);
	}
	return v;
}


// ROM
void GenChallengeROM_from_single_proof(unsigned char hash[ZKBOO_HASH_BYTES] /*OUT*/,
		const std::string &proof_commitment_full){
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, proof_commitment_full.data(), proof_commitment_full.size());
	SHA256_Final(hash, &ctx);
}



// Opt.6 Not including full views.
bool zkbpp_is_reconstruct_required(const MpcPartyContext* ctx[2]){
	return ctx[0]->view.output32.size() != ctx[1]->view.output32.size()
			|| ctx[0]->view.output64.size() != ctx[1]->view.output64.size();
}


template class MpcVariable<uint8_t>;
template class MpcVariable<uint32_t>;
template class MpcVariable<uint64_t>;
template class MpcVariableVerify<uint8_t>;
template class MpcVariableVerify<uint32_t>;
template class MpcVariableVerify<uint64_t>;

