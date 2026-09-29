// C++ libraries
#include <iostream>
#include <bitset>
#include <vector>
#include <string>
#include <iomanip>
using namespace std;

#pragma once
class Hash
{
public:
	// Hash length
	size_t h_length;
	// Field length
	size_t field_length;
	// 32 bit blocks
	bitset<32> block;
	bitset<32> last_block;
	// Current and old bit list and storage
	vector<bitset<8>> bit_list;
	vector<bitset<8>> old_list;
	vector<bitset<8>> check_list;
	// Iteration value, constant and bool password check
	int iteration;
	unsigned int constant1 = 0xB4;
	bool correct;

	// Constructor, deconstructor, setter and functions
	Hash();
	~Hash();
	void set_it(int i);
	void hash(string key);
	void padding(string& key);
	void key_length(string& key, size_t field_length, size_t k_length_bits);
	void make_block(bitset<8> block1, bitset<8> block2, bitset<8> block3, bitset<8> block4);
	void avalanche(bitset<32>& block);
	void display(vector<bitset<8>>& list);
	void calculation(vector<bitset<8>>& list, int it_num);
	void check_password(vector<bitset<8>> list1, vector<bitset<8>> list2);
	// Operation functions
	void twiddle_left(bitset<8>& key);
	void rotate_left(bitset<8>& key);
	void dynamic_left(bitset<8>& key, int rotate);
	void twiddle_right(bitset<8>& key);
	void rotate_right(bitset<8>& key);
	void dynamic_right(bitset<8>& key, int rotate);
};