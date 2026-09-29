// Custom Password Hash system

// Include class header
#include "Hash.h"

int main() {
	// Variables and objects
	string password;
	Hash hash_ob;
	int iteration;

	// User password input
	cout << "Set a password: " << endl;
	cin >> password;

	// User iteration input
	cout << "Enter a power value: " << endl;
	cin >> iteration;

	// Set iteration count and start hash algorithm 
	hash_ob.set_it(iteration);
	hash_ob.hash(password);

	// Store hash value for testing
	vector<bitset<8>> stored = hash_ob.check_list;
	cout << endl;

	// User testing input
	cout << "Enter a password to login: " << endl;
	cin >> password;
	// Start hash function
	hash_ob.hash(password);

	// Store hash value for testing
	vector<bitset<8>> login = hash_ob.check_list;

	// Hash value comparison 
	hash_ob.check_password(stored, login);

	return 0;
}