#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "domain_parameters.h"
#include "point.h"
#include "sha1.h"
#include "signature.h"
#include "test.h"
#include "benchmark.h"
#include "curves.h"

/*Program version number*/
#define VERSION "1.0.0"

/*Default curve, used when no -c/--curve parameter is defined*/
#define DEFAULT_CURVE secp160r1

/*Operating system dependent null device, /dev/null on Linux*/
#define NULL_DEVICE "/dev/null"

//Commands
int command_undefined(int argc, char* argv[]);
int command_generate(int argc, char* argv[]);
int command_sign(int argc, char* argv[]);
int command_verify(int argc, char* argv[]);
int command_crack(int argc, char* argv[]);
int command_benchmark(int argc, char* argv[]);
int command_test(int argc, char* argv[]);
int command_test_generate(int argc, char* argv[]);
int command_test_verify(int argc, char* argv[]);
int command_test_compression(int argc, char* argv[]);
int command_test_self(int argc, char* argv[]);
int command_test_number_theory(int argc, char* argv[]);
int command_help(int argc, char* argv[]);
int command_version(int argc, char* argv[]);

//Helpers

/*Get message from file or stdin, depending on parameters*/
void get_message(mpz_t m, int argc, char* argv[]);

/*Load domain_parameters depending on curve defined as parameter*/
domain_parameters get_curve(int argc, char* argv[]);

/*Is the parameter given, primarily used for parameters without arguments*/
bool is_parameter_defined(int argc, char* argv[], char* parameter);

/*Reads optional parameter from argument list, or asks for the parameter using stdin/stdout*/
char* read_optional_parameter_or_ask(int argc, char* argv[], char* parameter, char* question, char EndChar);

/*Reads optional parameter from argument list, returns NULL of no parameter available*/
char* read_optional_parameter(int argc, char* argv[], char* parameter);

/*Asks for parameter using stdin/stdout*/
char* ask_for_parameter(char* question, char EndChar);

/*Load output file, depending on parameter*/
FILE* get_output(int argc, char* argv[]);

/*Main function*/
int main(int argc, char *argv[])
{
	//Default return value, means internal inconsistency
	int return_value = 4;

	//Execute command depending on parameters
	if(argc == 1){
		return_value = command_undefined(argc, argv);
	}else if(!strcmp(argv[1],"--generate") || !strcmp(argv[1],"-g")){
		return_value = command_generate(argc, argv);
	}else if(!strcmp(argv[1],"--sign") || !strcmp(argv[1],"-s")){
		return_value = command_sign(argc, argv);
	}else if(!strcmp(argv[1],"--verify")){
		return_value = command_verify(argc, argv);
	}else if(!strcmp(argv[1],"--crack")){
		return_value = command_crack(argc, argv);
	}else if(!strcmp(argv[1],"--benchmark") || !strcmp(argv[1],"-b")){
		return_value = command_benchmark(argc, argv);
	}else if(!strcmp(argv[1],"--test") || !strcmp(argv[1],"-t")){
		return_value = command_test(argc, argv);
	}else if(!strcmp(argv[1],"--test-generate")){
		return_value = command_test_generate(argc, argv);
	}else if(!strcmp(argv[1],"--test-verify")){
		return_value = command_test_verify(argc, argv);
	}else if(!strcmp(argv[1],"--test-compression")){
		return_value = command_test_compression(argc, argv);
	}else if(!strcmp(argv[1],"--test-numbertheory")){
		return_value = command_test_number_theory(argc, argv);
	}else if(!strcmp(argv[1],"--test-self")){
		return_value = command_test_self(argc, argv);
	}else if(!strcmp(argv[1],"--help") || !strcmp(argv[1],"-h")){
		return_value = command_help(argc, argv);
	}else if(!strcmp(argv[1],"--version") || !strcmp(argv[1],"-v")){
		return_value = command_version(argc, argv);
	}else{
		return_value = command_undefined(argc, argv);
	}

	//Return return value from command
	return return_value;
}

/*Command undefined, or failed reading parameters*/
int command_undefined(int argc, char* argv[])
{
	fprintf(stderr, "%s: Missing arguments.\n", argv[0]);
	fprintf(stdout, "Try '%s --help' for further information.\n", argv[0]);
}

/*Command generate public key*/
int command_generate(int argc, char* argv[])
{
	//Get output file
	FILE* out = get_output(argc, argv);

	//Load domain parameters
	domain_parameters curve = get_curve(argc, argv);

	//Get private key
	char* str_key = read_optional_parameter(argc, argv, "-g");
	if(str_key == NULL)
		str_key = read_optional_parameter_or_ask(argc, argv, "--generate", "Private key:", '\n');
	char* str_hash = sha1(str_key);
	mpz_t key;mpz_init(key);
	mpz_set_str(key, str_hash, 16);
	free(str_hash); //Release memory
	free(str_key);

	//key modulo n
	mpz_t temp; mpz_init(temp);
	mpz_mod(temp, key, curve->n);
	mpz_set(key, temp);
	mpz_clear(temp);

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//Initialise public key
	point Q = point_init();

	//Generate public key		
	signature_generate_key(Q, key, curve);

	//Print compressed public key
	char* pubkey = point_compress(Q);

	//Write output
	if(quite)
		fputs(pubkey, out);
	else
		fprintf(out, "Public key:\n%s\n", pubkey);

	//Release memory
	domain_parameters_clear(curve);
	point_clear(Q);
	mpz_clear(key);
	free(pubkey);
	fclose(out);

	//Let's hope it went well, return 0
	return 0;
}

/*Command sign, generate signature*/
int command_sign(int argc, char* argv[])
{
	//Get output file
	FILE* out = get_output(argc, argv);

	//Load domain parameters
	domain_parameters curve = get_curve(argc, argv);

	//Get private key
	char* str_key = read_optional_parameter(argc, argv, "-s");
	if(str_key == NULL)
		str_key = read_optional_parameter_or_ask(argc, argv, "--sign", "Private key:", '\n');
	char* str_hash = sha1(str_key);
	mpz_t key;mpz_init(key);
	mpz_set_str(key, str_hash, 16);
	free(str_hash); //Release memory
	free(str_key);

	//key modulo n
	mpz_t temp; mpz_init(temp);//Is cleared later
	mpz_mod(temp, key, curve->n);
	mpz_set(key, temp);

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//Read message
	mpz_t m;mpz_init(m);
	get_message(m, argc, argv);

	//message modulo n
	mpz_mod(temp, m, curve->n);
	mpz_set(m, temp);
	mpz_clear(temp);
/*Acoording to Guide to Elliptic Curve Cryptography, one should truncate m to have the same bit-length as n. But it's this implementating is not completely compatable with standarts anyway. So modulo n oght to be just as good.*/

	//Generate signature
	signature sig = signature_init();
	signature_sign(sig, m, key, curve);

	//Print result
	if(quite)
	{
		fprintf(out, "R:");
		mpz_out_str(out, 16, sig->r);
		fprintf(out, "\nS:");
		mpz_out_str(out, 16, sig->s);
		fprintf(out, "\n");
	}else{
		fprintf(out, "Signature:\n\tR:");
		mpz_out_str(out, 16, sig->r);
		fprintf(out, "\n\tS:");
		mpz_out_str(out, 16, sig->s);
		fprintf(out, "\n");		
	}

	//Release memory
	domain_parameters_clear(curve);
	mpz_clear(key);
	mpz_clear(m);
	fclose(out);

	//Well that went well, return 0
	return 0;
}

/*Command verify signature*/
int command_verify(int argc, char* argv[])
{
	//Get output file
	FILE* out = get_output(argc, argv);

	//Load domain parameters
	domain_parameters curve = get_curve(argc, argv);

	//Get public key
	char* zkey = read_optional_parameter_or_ask(argc, argv, "--verify", "Public key:", '\n');
	point Q = point_init();
	point_decompress(Q, zkey, curve);
	free(zkey);

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//Read message
	mpz_t m;mpz_init(m);
	get_message(m, argc, argv);

	//message modulo n
	mpz_t temp; mpz_init(temp);
	mpz_mod(temp, m, curve->n);
	mpz_set(m, temp);
	mpz_clear(temp);
/*Acoording to Guide to Elliptic Curve Cryptography, one should truncate m to have the same bit-length as n. But it's this implementating is not completely compatable with standarts anyway. So modulo n oght to be just as good.*/

	//Read signature
	char* str_r = ask_for_parameter("Signature R:", '\n');
	char* str_s = ask_for_parameter("Signature S:", '\n');
	signature sig = signature_init();
	signature_set_str(sig, str_r, str_s, 16);
	free(str_r);
	free(str_s);

	//Verify signature
	bool result = signature_verify(m, sig, Q, curve);

	//If not quite write result, if quite result must be read from return value
	if(!quite)
	{
		if(result)
			fprintf(out, "Signature is valid.\n");
		else
			fprintf(out, "Signature is NOT valid!\n");
	}

	//Release memory
	domain_parameters_clear(curve);
	point_clear(Q);
	mpz_clear(m);
	fclose(out);

	//Return depending on signature verification
	if(result)
		return 0;
	else
		return 1;
}

/*Command crack, tries to crack a public key*/
int command_crack(int argc, char* argv[])
{
	//Get output file
	FILE* out = get_output(argc, argv);

	//Load domain parameters
	domain_parameters curve = get_curve(argc, argv);

	//Get private key
	char* zkey = read_optional_parameter_or_ask(argc, argv, "--crack", "Public key:", '\n');
	point Q = point_init();
	point_decompress(Q, zkey, curve);
	free(zkey);

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//A guessing point
	point guess = point_init();
	point_set(guess, curve->G);

	//A second guessing point explanation follows
	point guess2 = point_init();

	//Initialize two counter
	mpz_t i; mpz_init(i);
	mpz_t i2; mpz_init(i2);
	mpz_set_ui(i, 0);

	//If not quite print a warning
	if(!quite)
		fprintf(out, "WARNING: You are running a brute force attack on the elliptic curve discrete logarithm problem. This might take a minor eternity, press ctrl+c to abort.\nFactors checked: ");
	/*No seriously it'll probably take a minor eternity!*/

	//i, to be showen in terminal
	int i_i = 0;
	/*If anybody seriously wants to crack using this program, this variable will have an overflow, but that doesn't matter*/
	int printed = 0;//Chars to delete from stdout

	//Start an infinte loop
	while(true)
	{
		//Break the loop if our guess matches the public key
		if(point_cmp(guess,Q))
			break;

		//Add G to the guess, store it in guess two (it can't be stored in guess)
		point_addition(guess2, guess, curve->G, curve);

		//Add one to our counter
		mpz_add_ui(i2, i, 1);

		//Break the loop if our guess matches the public key
		if(point_cmp(guess2,Q))
			break;

		//Add G to the guess2, store it in guess (it can't be stored in guess2)
		point_addition(guess, guess2, curve->G, curve);

		//Add one to our counter
		mpz_add_ui(i, i2, 1);

		//Write a message to see just how far we are
		if(!quite)
		{
			while(printed>0)
			{
				printf("\b");//Write backspace char to clear out the terminal
				printed--;
			}
			printed = fprintf(stdout, "%i", i_i);
			i_i += 2;
		}
	}
	/*I could have used a temporary point instead of guess2, and then just copied the temporary guess to guess before repeating the loop, this would have made the loop steps shorter, but require unnesecary memory copying.*/

	//The biggest counter holds the result
	if(mpz_cmp(i,i2) < 0)
		mpz_set(i, i2);

	//If we get this far, then we did actually crack it! Let's display result
	if(quite)
	{
		mpz_out_str(out, 16, i);
	}else{
		fprintf(out, "Hashsum of the private key is:\n");
		mpz_out_str(out, 16, i);
		fprintf(out, "\n");
	}

	/*Yes, i is just the hashsum of the private key to be entered to this application, however this is enough! Since this application only takes the sha1sum of the private key to transform it into an integer that can be used for signature generation. Thus anyone possessing the sha1sum of the private key, can rewrite this simple program to not take sha1sum before calculating signatures. Hence there's no security in the sha1 transformation of the private key.*/

	//Release memory
	domain_parameters_clear(curve);
	point_clear(Q);
	point_clear(guess);
	mpz_clear(i);
	fclose(out);
}

/*Command benchmark*/
int command_benchmark(int argc, char* argv[])
{
	//Get output file
	FILE* out = get_output(argc, argv);

	//Read benchmark illiterator
	int i = 0;
	char* str_i = read_optional_parameter(argc, argv, "-b");
	if(str_i == NULL)
		str_i = read_optional_parameter(argc, argv, "--benchmark");
	if(str_i != NULL)
		sscanf(str_i, "%i", &i);

	//Run benchmark
	benchmark(out, i);

	//Release memory
	fclose(out);
	free(str_i);

	//Return 0
	return 0;
}

/*Command test, runs all test*/
int command_test(int argc, char* argv[])
{
	//output file, loaded later depending on quite mode
	FILE* out;

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//If we're in quite mode, load null device and print to it
	if(quite)
	{
		out = fopen(NULL_DEVICE, "w");
		if(out == NULL)
		{
			fprintf(stderr, "%s: Can't open NULL_DEVICE, used in quite mode testing.", argv[0]);
			exit(2);
		}
	}else{
		//Load output file
		out = get_output(argc, argv);
	}

	//Really run the test
	bool result = test(out);

	//Close output file
	fclose(out);

	//Return value depending on test success
	if(result)
		return 0;
	else
		return 1;
}

/*Command test, tests public key generation*/
int command_test_generate(int argc, char* argv[])
{
	//output file, loaded later depending on quite mode
	FILE* out;

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//If we're in quite mode, load null device and print to it
	if(quite)
	{
		out = fopen(NULL_DEVICE, "w");
		if(out == NULL)
		{
			fprintf(stderr, "%s: Can't open NULL_DEVICE, used in quite mode testing.", argv[0]);
			exit(2);
		}
	}else{
		//Load output file
		out = get_output(argc, argv);
	}

	//Really run the test
	bool result = test_key_generation(out);

	//Close output file
	fclose(out);

	//Return value depending on test success
	if(result)
		return 0;
	else
		return 1;
}

/*Command test, tests verification*/
int command_test_verify(int argc, char* argv[])
{
	//output file, loaded later depending on quite mode
	FILE* out;

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//If we're in quite mode, load null device and print to it
	if(quite)
	{
		out = fopen(NULL_DEVICE, "w");
		if(out == NULL)
		{
			fprintf(stderr, "%s: Can't open NULL_DEVICE, used in quite mode testing.", argv[0]);
			exit(2);
		}
	}else{
		//Load output file
		out = get_output(argc, argv);
	}

	//Really run the test
	bool result = test_verification(out);

	//Close output file
	fclose(out);

	//Return value depending on test success
	if(result)
		return 0;
	else
		return 1;
}

/*Command test, tests compression*/
int command_test_compression(int argc, char* argv[])
{
	//output file, loaded later depending on quite mode
	FILE* out;

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//If we're in quite mode, load null device and print to it
	if(quite)
	{
		out = fopen(NULL_DEVICE, "w");
		if(out == NULL)
		{
			fprintf(stderr, "%s: Can't open NULL_DEVICE, used in quite mode testing.", argv[0]);
			exit(2);
		}
	}else{
		//Load output file
		out = get_output(argc, argv);
	}

	//Really run the test
	bool result = test_compression(out);

	//Close output file
	fclose(out);

	//Return value depending on test success
	if(result)
		return 0;
	else
		return 1;
}

/*Command test, run self test*/
int command_test_self(int argc, char* argv[])
{
	//output file, loaded later depending on quite mode
	FILE* out;

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//If we're in quite mode, load null device and print to it
	if(quite)
	{
		out = fopen(NULL_DEVICE, "w");
		if(out == NULL)
		{
			fprintf(stderr, "%s: Can't open NULL_DEVICE, used in quite mode testing.", argv[0]);
			exit(2);
		}
	}else{
		//Load output file
		out = get_output(argc, argv);
	}

	//Really run the test
	bool result = test_self(out);

	//Close output file
	fclose(out);

	//Return value depending on test success
	if(result)
		return 0;
	else
		return 1;
}

/*Command test, test number theory implementation*/
int command_test_number_theory(int argc, char* argv[])
{
	//output file, loaded later depending on quite mode
	FILE* out;

	//Are we running quite mode
	bool quite = is_parameter_defined(argc, argv, "--quite");
	if(!quite)
		quite = is_parameter_defined(argc, argv, "-q");

	//If we're in quite mode, load null device and print to it
	if(quite)
	{
		out = fopen(NULL_DEVICE, "w");
		if(out == NULL)
		{
			fprintf(stderr, "%s: Can't open NULL_DEVICE, used in quite mode testing.", argv[0]);
			exit(2);
		}
	}else{
		//Load output file
		out = get_output(argc, argv);
	}

	//Really run the test
	bool result = test_number_theory(out);

	//Close output file
	fclose(out);

	//Return value depending on test success
	if(result)
		return 0;
	else
		return 1;
}

/*Command help, displays help information*/
int command_help(int argc, char* argv[])
{
	//Short usage introduction
	printf("Usage: %s <command> [options]\nGenerate public key, sign and verify messages using the elliptic curve digital signature algorithm.\n\n", argv[0]);

	//List all commands and a short description
	printf("Commands:\n");
	printf(" -g [key] --generate [key]    Generate public key\n");
	printf(" -s [key] --sign [key]        Sign a message\n");
	printf("          --verify [key]      Verify signature\n");
	printf(" -b [key] --benchmark [i]     Run a benchmark\n");
	printf(" -t       --test              Run all tests\n");
	printf("          --test-generate     Test public key generation\n");
	printf("          --test-verify       Test signature verification\n");
	printf("          --test-compression  Test point compression\n");
	printf("          --test-numbertheory Test point compression\n");
	printf("          --test-self         Run self test\n");
	printf("          --crack [key]       Try to crack a public key\n");
	printf(" -v       --version           Display version information\n");
	printf(" -h       --help              Display help.\n");

	//List all options and a short description
	printf("\nOptions:\n");
	printf(" -c <curve> --curve <curve>   Curve [0-%i], defaults to DEFAULT_CURVE = %i\n", NUMBER_OF_CURVES - 1, DEFAULT_CURVE);
	printf(" -I <file>  --input <file>    Input file, defaults to stdin\n");
	printf(" -O <file>  --output <file>   Output file, defaults to stdout\n");
	printf(" -q         --quite           Quite mode\n");

	//List return values
	printf("\nReturn values:\n");
	printf(" 0  Operation performed successfully\n");
	printf(" 1  Verification or test failed, program ended without failure\n");
	printf(" 2  File IO failure, see stderr\n");
	printf(" 3  Out of memory error\n");			//This won't occur, since I didn't borther to check if every memory resevation went well, I might check some later on
	printf(" 4  Internal inconsistency\n");			//Shouldn't be possible
	printf(" 5  Not implemented yet\n");			//Doesn't occur anymore, since development is done.

	//Print a final notice about this application
	printf("\nSimpleECDSA is a simple implementation of ECDSA, it's NOT designed to solve security issues. It's an educational toy, designed to play with performance and implementation issue of ECDSA.\n");

	//return null, this didn't fail (if it did, the program's already dead).
	return 0;
}

/*Command version, displays version information*/
int command_version(int argc, char* argv[])
{
	fprintf(stdout , "%s (SimpleECDSA) %s\nCopyright (C) 2007 Jonas F. Jensen.\nThis is free software. You may redistribute copies of it under the terms of\nthe GNU General Public License <http://www.gnu.org/licenses/gpl.html>.\nThere is NO WARRANTY, to the extent permitted by law.\n\nWritten by Jonas F. Jensen <Jopsen@gmail.com>.\n", argv[0], VERSION);
	return 0;
}

/*Is the parameter given, primarily used for parameters without arguments*/
bool is_parameter_defined(int argc, char* argv[], char* parameter)
{
	//Loop through parameters to see if the one we're looking for is defined
	int i;
	for(i = 1; i < argc; i++)
	{
		if(!strcmp(argv[i], parameter))
			return true;
	}
	return false;
}

/*Get message from file or stdin, depending on parameters*/
void get_message(mpz_t m, int argc, char* argv[])
{
	//Read parameters
	char* str_input = read_optional_parameter(argc, argv, "-I");
	if(str_input == NULL)
		str_input = read_optional_parameter(argc, argv, "--input");

	//Variable for data read
	char* str_data;

	//If parameters not null try reading them
	if(str_input != NULL)
	{
		FILE* f_input = fopen(str_input, "r");
		if(f_input == NULL)
		{
			fprintf(stderr, "%s: Can't open input file: %s\n", argv[0], str_input);
			exit(2);
		}
		free(str_input);	//Release memory

		//find length of the file
		fseek(f_input, 0, SEEK_END);
		int len = ftell(f_input);
		rewind(f_input);

		//Allocate memory
		str_data = (char*)malloc(len+1);
		str_data[len] = '\0';

		//Read file
		int read = fread(str_data, 1, len, f_input);

		//Check what we've read
		if(read != len)
		{
			fprintf(stderr, "%s: Failed to read input file corretly %i of %i bytes were read.\n", argv[0], read, len);
			exit(2);
		}

		//Close file
		fclose(f_input);
	}else{
		//Read from stdin
		str_data = ask_for_parameter("Message:", EOF);
	}

	//Compute hash
	char* hash = sha1(str_data);

/*This program is not suited for large files since the integer file is loaded into memory before the sha1 hash is calculated. Sha1 is designed so that one could load the input file in small portions and calculate the sha1 sum as the file is read. The file I'm using for calculate sha1 sum actually features this, but to keep things simple I've decided to do it this way. Because testing performance of signing big files is not the purpose of this project, if that was the case it should have been a project about sha1 and hash performance.*/


	//Release memory
	free(str_data);

	//Load hashsum as number
	mpz_set_str(m, hash, 16);

	//Release memory
	free(hash);
}

/*Load domain_parameters depending on curve*/
domain_parameters get_curve(int argc, char* argv[])
{
	//Set default curve
	int curve_parameter = DEFAULT_CURVE;

	//Read parameters
	char* str_curve = read_optional_parameter(argc, argv, "-c");
	if(str_curve == NULL)
		str_curve = read_optional_parameter(argc, argv, "--curve");

	//Did we get a parameter
	if(str_curve != NULL)
	{
		//try to read parameter
		sscanf(str_curve, "%i", &curve_parameter);
		//Validate parameter
		if(curve_parameter > NUMBER_OF_CURVES - 1)
			curve_parameter = DEFAULT_CURVE;
		//Release memory
		free(str_curve);
	}

	//Load domain parameter depending on curve
	domain_parameters curve = domain_parameters_init();
	domain_parameters_load_curve(curve, curve_parameter);

	//Return domain parameters
	return curve;
}

/*Load output file, depending on parameter*/
FILE* get_output(int argc, char* argv[])
{
	//Output file
	FILE* out = stdout;

	//Read the parameter
	char* strout = read_optional_parameter(argc, argv, "--output");
	if(strout == NULL)
	{
		strout = read_optional_parameter(argc, argv, "--O");
	}

	if(strout != NULL)
	{
		out = fopen(strout, "w");
		if(out == NULL)
		{
			fprintf(stderr, "%s: Can't open output file: %s\n", argv[0], strout);
			exit(2);
		}
		free(strout);
	}

	return out;
}

/*Reads optional parameter from argument list, or asks for the parameter using stdin/stdout*/
char* read_optional_parameter_or_ask(int argc, char* argv[], char* parameter, char* question, char EndChar)
{
	char* value = read_optional_parameter(argc, argv, parameter);
	if(value == NULL)
		return ask_for_parameter(question, EndChar);
	else
		return value;
}

/*Reads optional parameter from argument list, returns NULL of no parameter available*/
char* read_optional_parameter(int argc, char* argv[], char* parameter)
{
	//Set value to null
	char* value = NULL;

	//Loop through parameters
	int i;
	for(i = 1; i < argc; i++)
	{
		//Check if this is our parameter
		if(!strcmp(argv[i], parameter) && argc > i+1 && strncmp(argv[i+1],"-",1))
		{
			//Reserve memory
			int len = strlen(argv[i+1]);
			value = (char*)malloc(len+1);
			value[len] = '\0';

			//Copy data
			strcpy(value, argv[i+1]);

			//Break
			break;
		}
	}

	//Return value
	return value;
}

/*Asks for parameter using stdin/stdout*/
char* ask_for_parameter(char* question, char EndChar)
{
	//Ask the question:
	puts(question);

	//Read string from stdin
	char* value = NULL;
	char temp;
	int i = 0;
	while(1)
	{
		temp = getchar();
		if(temp == EndChar || temp == EOF)
			break;
		value = (char*) realloc(value, i + 1);
		value[i] = temp;
		i++;
	}
	value[i] = '\0';

	//if last char != newline, write newline to beautify potential output in stdout
	if(temp != '\n')
		putchar('\n');

	//Return value
	return value;
}
