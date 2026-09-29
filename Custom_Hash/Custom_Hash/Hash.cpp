#include "Hash.h"

// Constructor and variable initilisation
Hash::Hash() {
	h_length = 32;
	field_length = 4;
	block = 0;
	last_block = 0;
	iteration = 0;
	correct = false;
}

// Deconstructor
Hash::~Hash() {
}

// Set iteration number
void Hash::set_it(int i) {
	iteration = i;
}

// Hash function
void Hash::hash(string key) {
	// Clear vector and variables
	bit_list.clear();
	block.reset();
	last_block.reset();

	// Pad plaintext password
	padding(key);

	// Make blocks of 32 bits
	for (int x = 0; x < key.size(); x = x + 4) {
		bitset<8> bit_key1(key.at(x));
		bitset<8> bit_key2(key.at(x + 1));
		bitset<8> bit_key3(key.at(x + 2));
		bitset<8> bit_key4(key.at(x + 3));
		make_block(bit_key1, bit_key2, bit_key3, bit_key4);

		// Use of block chaining to further avalanche 
		block ^= last_block;
		avalanche(block);
		last_block = block;

		// Convert 32 bit block back into 8 bit blocks
		bitset<8> bk1((block >> 24).to_ulong() & 0xFF);
		bitset<8> bk2((block >> 16).to_ulong() & 0xFF);
		bitset<8> bk3((block >> 8).to_ulong() & 0xFF);
		bitset<8> bk4((block).to_ulong() & 0xFF);

		// Add 8 bit blocks to list
		bit_list.push_back(bk1);
		bit_list.push_back(bk2);
		bit_list.push_back(bk3);
		bit_list.push_back(bk4);
	}

	// Call calculation to further scramble and display to print to the user 
	calculation(bit_list, iteration);
	display(bit_list);
	check_list = bit_list;
}

// Key padding
void Hash::padding(string& key) {
	// Padding in a similar method to the SHA system
	// Add "1" to the end of the og key, continue with "0", then add the original key length to the end, making sure it is 32 bytes long
	if (key.length() < h_length) {
		// Store key length in bits
		size_t k_length_bits = key.length() * 8;
		// Add "1" to the end of the original key
		key.push_back(0x01);
		// Add "0" till the start of the field length is reached
		while (key.length() < (h_length - field_length)) {
			key.push_back(0x00);
		}
		key_length(key, field_length, k_length_bits);
	}
}

// Append key length
void Hash::key_length(string& key, size_t field_length, size_t k_length_bits)
{
	// Sort key length with largest byte first, then push back onto the field length of the original key
	for (int x = field_length - 1; x >= 0; x--)
	{
		bitset<8> byte = (k_length_bits >> (x * 8)) & 0xFF;
		key.push_back(static_cast<char>(byte.to_ulong()));
	}
}

// Make a 32 bit block
void Hash::make_block(bitset<8> block1, bitset<8> block2, bitset<8> block3, bitset<8> block4) {
	bitset<32> value;

	// Shift each 8 bit block to create a 32 bit block
	value |= (static_cast<uint64_t>(block1.to_ulong() << 24));
	value |= (static_cast<uint64_t>(block2.to_ulong() << 16));
	value |= (static_cast<uint64_t>(block3.to_ulong() << 8));
	value |= (block4.to_ulong());

	block = value;
}

// Avalanche 
void Hash::avalanche(bitset<32>& block) {
	// Static cast block to uint32_t for mathematical operations 
	uint32_t temp = static_cast<uint32_t>(block.to_ulong());
	// Avalanche with a mixture of XOR, bit shifting and mathematical operations
	temp ^= temp >> 15;
	temp *= 0x7672BE93u;
	temp ^= temp >> 12;
	temp *= 0x2CC2079Bu;
	temp ^= temp >> 15;
	block = bitset<32>(temp);
}

// Display hash in hexadecimal form
void Hash::display(vector<bitset<8>>& list) {
	for (bitset<8> byte : list)
	{
		cout << hex << setw(2) << setfill('0') << static_cast<int>(byte.to_ulong());
	}
}

// Scramble each byte of the padded key
void Hash::calculation(vector<bitset<8>>& list, int it_num) {
	old_list = list;
	vector<bitset<8>> new_list(list.size());

	// Loops for scrambling
	for (int z = 0; z < it_num; z++) {
		for (int x = 0; x < old_list.size(); x++) {
			uint8_t temp = old_list.at(x).to_ulong();
			temp = (temp + (x * 37 + constant1)) & 0xFF;
			new_list.at(x) = bitset<8>(temp);
		}
		for (int x = 0; x < old_list.size(); x++) {
			new_list.at(x) ^= old_list.at((x + 1) % 32);
			rotate_left(new_list.at(x));
		}
		for (int x = 0; x < old_list.size(); x++) {
			uint8_t temp = new_list.at(x).to_ulong();
			temp = (temp * 17) & 0xFF;
			new_list.at(x) = bitset<8>(temp);
			new_list.at(x) ^= old_list.at((x + 7) % 32);
		}
		for (int x = 0; x < old_list.size(); x++) {
			new_list.at(x) ^= old_list.at((x + 5) % 32);
			new_list.at(x) ^= old_list.at((x + 19) % 32);
		}
		old_list = new_list;
	}
	list = new_list;
}

// Check set password with login attempt
void Hash::check_password(vector<bitset<8>> list1, vector<bitset<8>> list2) {
	correct = false;
	for (int x = 0; x < list1.size(); x++) {
		if (list1.at(x) == list2.at(x)) {
			correct = true;
		}
	}
	if (correct) {
		cout << endl;
		cout << "Logging in..." << endl;
	}
	else {
		cout << endl;
		cout << "Incorrect Password." << endl;
	}
}

// Bit twiddle left
void Hash::twiddle_left(bitset<8>& key) {
	bitset<8> temp = key << 2;
	key = temp;
}

// Bit rotate left
void Hash::rotate_left(bitset<8>& key) {
	bitset<8> temp = (key << 1) | (key >> (32 - 1));
	key = temp;
}

// Dynamic bit rotate left
void Hash::dynamic_left(bitset<8>& key, int rotate) {
	bitset<8> temp = (key << rotate) | (key >> (32 - rotate));
	key = temp;
}

// Bit twiddle right
void Hash::twiddle_right(bitset<8>& key) {
	bitset<8> temp = key >> 2;
	key = temp;
}

// Bit rotate right
void Hash::rotate_right(bitset<8>& key) {
	bitset<8> temp = (key >> 1) | (key << (32 - 1));
	key = temp;
}

// Dynamic bit rotate right
void Hash::dynamic_right(bitset<8>& key, int rotate) {
	bitset<8> temp = (key >> rotate) | (key << (32 - rotate));
	key = temp;
}