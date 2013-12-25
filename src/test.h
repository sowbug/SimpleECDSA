/*Runs test using test vectors from GEC, result is printed to out, returns true if tests succed*/
bool test(FILE* out);

/*Test generation of public key using test vectors*/
bool test_key_generation(FILE* out);

/*Tests verification of signature from test vectors*/
bool test_verification(FILE* out);

/*Tests point compression, thus squareroots modulo prime*/
bool test_compression(FILE* out);

/*Runs signs and verifies a message, using random key*/
bool test_self(FILE* out);

/*Test number theory implementation*/
bool test_number_theory(FILE* out);

/*Number of times to repeat number theory tests with random integers*/
#define TEST_STEPS 500

/*Biggest number that may be used running number theory tests*/
#define BIGGEST_TEST_NUMBER "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
