#include <stdlib.h>
#include <stdio.h>
#include <gmp.h>
#include <stdbool.h>
#include <time.h>
#include "domain_parameters.h"
#include "point.h"
#include "signature.h"
#include "test.h"
#include "curves.h"
#include "random.h"
#include "numbertheory.h"

/*Runs test using test vectors from GEC, result is printed to out returns true if tests succed*/
bool test(FILE* out)	//Set out to /dev/null if quite mode is requested (must be done in main)
{
	//Start timing
	clock_t start = clock();

	//Run tests
	if(!test_key_generation(out))
		return false;
	if(!test_verification(out))
		return false;
	if(!test_self(out))
		return false;
	if(!test_compression(out))
		return false;
	if(!test_number_theory(out))
		return false;

	//Write message and time
	double elapsed = ((double) (clock() - start)) / CLOCKS_PER_SEC;
	fprintf(out, "\n\nAll Test successfully completed in %.4f seconds.\n", elapsed);

	//Return true
	return true;
}

/*Test generation of public key using test vectors*/
bool test_key_generation(FILE* out)
{
	//First notice
	fprintf(out, "\n--- Test public key generation ---\n");

	//Setting up domain parameters
	domain_parameters curve = domain_parameters_init();
	domain_parameters_load_curve(curve, secp160r1);

	//Public key
	point Q = point_init();
	point Q_check = point_init();

	//Private key
	mpz_t d;mpz_init(d);

	//Load key from GEC test vectors
	mpz_set_str(d, "971761939728640320549601132085879836204587084162", 10);

	//Load correct result from GEC test vectors
	point_set_str(Q_check, "466448783855397898016055842232266600516272889280", "1110706324081757720403272427311003102474457754220", 10);

	//Generate public key
	signature_generate_key(Q, d, curve);

	//Place holder for result
	bool result = point_cmp(Q,Q_check);

	//Verify the result of the generation
	if(result)
		fprintf(out,"Test completed successfully.\n");
	else
		fprintf(out,"Test failed!\n");

	//Release memory
	point_clear(Q);
	point_clear(Q_check);
	domain_parameters_clear(curve);
	mpz_clear(d);

	//Return result
	return result;
}

/*Tests verification of signature from test vectors*/
bool test_verification(FILE* out)
{
	//First notice
	fprintf(out, "\n--- Test signature verification ---\n");

	//Setting up domain parameters
	domain_parameters curve = domain_parameters_init();
	domain_parameters_load_curve(curve, secp160r1);

	//Public key
	point Q = point_init();

	//Message
	mpz_t m;mpz_init(m);

	//Signature
	signature sig = signature_init();

	//Message hash from test vectors
	mpz_set_str(m, "968236873715988614170569073515315707566766479517", 10);

	//Load signature
	signature_set_str(sig, "1176954224688105769566774212902092897866168635793", "299742580584132926933316745664091704165278518100", 10);

	//Load public key
	point_set_str(Q, "466448783855397898016055842232266600516272889280", "1110706324081757720403272427311003102474457754220", 10);

	//Result
	bool result = signature_verify(m, sig, Q, curve);

	//Write result to out
	if(result)
		fprintf(out,"Test completed successfully.\n");
	else
		fprintf(out,"Test failed!\n");

	//Release memory
	mpz_clear(m);
	point_clear(Q);
	signature_clear(sig);
	domain_parameters_clear(curve);

	//Return result
	return result;
}

/*Tests point compression, thus squareroots modulo prime*/
bool test_compression(FILE* out)
{
	//First notice
	fprintf(out, "\n--- Test point compression ---\n");

	int i;
	int bad_curves = 0;

	//Loop thruogh all curves to test square root in them.	
	for(i = 0;i < NUMBER_OF_CURVES;i++)
	{
		//Load curve
		domain_parameters curve = domain_parameters_init();
		domain_parameters_load_curve(curve, i);

		//Print curve name
		fprintf(out, "%s: ", curve->name);

		//Compress base point
		char* zPoint = point_compress(curve->G);

		//Initialize new point
		point P = point_init();

		//Decompress compressed base point
		point_decompress(P, zPoint, curve);

		//Verify compression
		if(point_cmp(P,curve->G))
			fprintf(out, "Ok");
		else
		{
			fprintf(out ,"Failed");
			bad_curves++;
		}

		//Clear variables
		domain_parameters_clear(curve);
		point_clear(P);
		free(zPoint);	//Release compressed base point

		//print a new line with CRLF
		fprintf(out, "\n");
	}
	if(bad_curves == 0)
		fprintf(out,"Test completed successfully.\n");
	else
		fprintf(out,"Test failed, %i curves didn't (de)compress correctly!\n", bad_curves);

	return bad_curves == 0;
}

/*Runs signs and verifies a message, using random key*/
bool test_self(FILE* out)
{
	//First notice
	fprintf(out, "\n--- Test algothrim integrity ---\n");

	//Setting up domain parameters
	domain_parameters curve = domain_parameters_init();
	domain_parameters_load_curve(curve, secp160r1);

	//Public key
	point Q = point_init();

	//Message
	mpz_t m;mpz_init(m);

	//Private key
	mpz_t d;mpz_init(d);

	//Signature
	signature sig = signature_init();

	//Message hash just a random number
	mpz_set_str(m, "2156842181254876268462177895321953219548746516484", 10);

	//Set private key to random integer
	gmp_randstate_t r_state;
	gmp_randinit_default(r_state);
	mpz_urandomm(d , r_state ,curve->n);
	gmp_randclear(r_state);

	//Generate signature
	signature_sign(sig, m, d, curve);

	//Generate public key
	signature_generate_key(Q, d, curve);

	//Verify result
	bool result = signature_verify(m, sig, Q, curve);

	//Write result to out
	if(result)
		fprintf(out,"Test completed successfully.\n");
	else
		fprintf(out,"Test failed!\n");

	//Release memory
	mpz_clear(m);
	mpz_clear(d);
	point_clear(Q);
	signature_clear(sig);
	domain_parameters_clear(curve);

	//Return result
	return result;
}

/*Test number theory implementation*/
bool test_number_theory(FILE* out)
{
	//First notice
	fprintf(out, "\n--- Test number theory ---\n");

	//Initialize random algorithm
	gmp_randstate_t rstate;
	gmp_randinit_default(rstate);
	//Feed it with random, else the number will ALLWAY be the same!
	random_seeding(rstate);

	//Biggest number that may be used 
	mpz_t top;mpz_init(top);
	mpz_set_str(top, BIGGEST_TEST_NUMBER, 16);

	//Initialize input variables for random integers
	mpz_t i1;mpz_init(i1);
	mpz_t i2;mpz_init(i2);	
	mpz_t i3;mpz_init(i3);

	//Initialize result variables
	mpz_t r1;mpz_init(r1);
	mpz_t r2;mpz_init(r2);

	//initialize temporary variables
	mpz_t t1;mpz_init(t1);
	mpz_t t2;mpz_init(t2);

	bool exp_mod = true, sqrt_mod = true, mul_inv = true, legendre = true;

	//Modular explonentiation
	int i;
	for(i = 0; i < TEST_STEPS; i++)
	{
		//Get random integers
		mpz_urandomm(i1, rstate, top);
		mpz_urandomm(i2, rstate, i1);
		mpz_urandomm(i3, rstate, i1);

		//Calculate i2^i3 mod i1 with two functions
		mpz_powm(r1, i2, i3, i1);
		number_theory_exp_modp(r2, i2, i3, i1);

		//Compare results
		if(mpz_cmp(r1, r2) != 0)
		{
			exp_mod = false;
			break;
		}
	}

	//Print a result
	if(exp_mod)
		fprintf(out, "Modular explonentiation:      Ok\n");
	else
		fprintf(out, "Modular explonentiation:      Failed!\n");

	//Squareroot
	for(i = 0; i < TEST_STEPS; i++)
	{
		//Get random input
		mpz_urandomm(i2, rstate, top);
		mpz_nextprime(i1, i2); //Make it a random prime
		mpz_urandomm(i2, rstate, i1);

		//r1 = i2^2 mod i1
		number_theory_exp_modp_ui(i3, i2, 2, i1);

		//Calculate square root
		number_theory_squareroot_modp(r1, i3, i1);

		//r2 = p - r1
		mpz_sub(r2, i1, r1);
		if(mpz_cmp(i2, r1) != 0 && mpz_cmp(i2, r2) != 0)
		{
			sqrt_mod = false;
			break;
		}		
	}

	//Print a result
	if(sqrt_mod)
		fprintf(out, "Squaring modulo prime:        Ok\n");
	else
		fprintf(out, "Squaring modulo prime:        Failed!\n");

	//Multiplicative inverses
	mpz_set_ui(r1, 1);
	for(i = 0; i < TEST_STEPS; i++)
	{
		//Get random input
		mpz_urandomm(i2, rstate, top);
		mpz_nextprime(i1, i2); //Make it a random prime
		mpz_urandomm(i2, rstate, i1);

		//Calculate inverse
		number_theory_inverse(t1, i2, i1);

		//Check it by multiplication: t1 * i2 mod i1 == 1
		mpz_mul(t2, t1, i2);	//t1 * i2
		mpz_mod(r2, t2, i1);

		//Compare results
		if(mpz_cmp(r1, r2) != 0)
		{
			mul_inv = false;
			break;
		}
	}

	//Print a result
	if(mul_inv)
		fprintf(out, "Extended euclidean algorithm: Ok\n");
	else
		fprintf(out, "Extended euclidean algorithm: Failed!\n");

	//Legendre symbol
	for(i = 0; i < TEST_STEPS; i++)
	{
		//Get random input
		mpz_urandomm(i2, rstate, top);
		mpz_nextprime(i1, i2); //Make it a random prime
		mpz_urandomm(i2, rstate, i1);

		//Compare results
		if(mpz_legendre(i2, i1) != number_theory_legendre(i2, i1))
		{
			printf("\np:");
			mpz_out_str(stdout, 10, i1);
			printf("\na:");
			mpz_out_str(stdout, 10, i2);
			printf("\n");
			legendre = false;
			break;
		}
	}

	//Print a result
	if(legendre)
		fprintf(out, "Legendre symbol test:         Ok\n");
	else
		fprintf(out, "Legendre symbol test:         Failed!\n");

	//End test result
	if(exp_mod && sqrt_mod && mul_inv && legendre)
		fprintf(out,"Number theory tests successfully completed %i times.\n",TEST_STEPS);
	else
		fprintf(out,"Number theory tests failed!\n");

	//Release memory
	gmp_randclear(rstate);
	mpz_clear(r1);
	mpz_clear(r2);
	mpz_clear(i1);
	mpz_clear(i2);
	mpz_clear(i3);
	mpz_clear(t1);
	mpz_clear(t2);

	//Return result of the testing
	return exp_mod && sqrt_mod && mul_inv && legendre;
}
