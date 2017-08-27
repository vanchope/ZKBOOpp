/*
 * Variable_test.cpp
 *
 *  Created on: Aug 31, 2016
 *      Author: ivan
 */
#include "MpcVariable.h"

#include <iostream>
using namespace std;


void test_convert_vector_string(){
	vector<string> vs;
	vs.push_back("a");
	vs.push_back("bbbb");
	vs.push_back("");
	vs.push_back("cc");

	string s = vectorstrings_to_string(vs);
	vector<string> vs2 = string_to_vectorstrings(s);
	assert(vs.size() == vs2.size());
	for(size_t i=0; i<vs.size(); i++){
		assert(vs[i].compare(vs2[i])==0);
	}
	cout << "test_convert_vector_string passed." << endl;
}


int main(){
	//cout << "MpcVariable, nothing to test." << endl;
	test_convert_vector_string();
}
