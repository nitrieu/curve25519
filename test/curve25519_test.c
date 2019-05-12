/* The MIT License (MIT)
*
* Copyright (c) 2015 mehdi sotoodeh
*
* Permission is hereby granted, free of charge, to any person obtaining
* a copy of this software and associated documentation files (the
* "Software"), to deal in the Software without restriction, including
* without limitation the rights to use, copy, modify, merge, publish,
* distribute, sublicense, and/or sell copies of the Software, and to
* permit persons to whom the Software is furnished to do so, subject to
* the following conditions:
*
* The above copyright notice and this permission notice shall be included
* in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
* IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
* CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
* TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
* SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include <stdio.h>
#include <stdlib.h>
#include "../include/external_calls.h"
#include "../source/curve25519_mehdi.h"
#include "curve25519_donna.h"
#include "../include/curve25519_dh.h"
#include "../include/ed25519_signature.h"
#include "../custom/random.h"

#ifdef USE_ASM_LIB

/* Defined in ASM library */
U64 readTSC();

#else
#if defined(_MSC_VER)
#include <intrin.h>
U64 readTSC()
{
	return __rdtsc();
}
#else
U64 readTSC()
{
	U64 tsc;
	__asm__ volatile(".byte 0x0f,0x31" : "=A" (tsc));
	return tsc;
}
#endif
#endif

void ecp_PrintBytes(IN const char *name, IN const U8 *data, IN U32 size)
{
	U32 i;
	printf("\nstatic const unsigned char %s[%d] =\n  { 0x%02X", name, size, *data++);
	for (i = 1; i < size; i++)
	{
		if ((i & 15) == 0)
			printf(",\n    0x%02X", *data++);
		else
			printf(",0x%02X", *data++);
	}
	printf(" };\n");
}

void ecp_PrintHexBytes(IN const char *name, IN const U8 *data, IN U32 size)
{
	printf("%s = 0x", name);
	while (size > 0) printf("%02X", data[--size]);
	printf("\n");
}

#ifdef WORDSIZE_64
void ecp_PrintWords(IN const char *name, IN const U64 *data, IN U32 size)
{
	U32 i;
	printf("\nstatic const U64 %s[%d] =\n  { 0x%016llX", name, size, *data++);
	for (i = 1; i < size; i++)
	{
		if ((i & 3) == 0)
			printf(",\n    0x%016llX", *data++);
		else
			printf(",0x%016llX", *data++);
	}
	printf(" };\n");
}

void ecp_PrintHexWords(IN const char *name, IN const U64 *data, IN U32 size)
{
	printf("%s = 0x", name);
	while (size > 0) printf("%016llX", data[--size]);
	printf("\n");
}
#else
void ecp_PrintWords(IN const char *name, IN const U32 *data, IN U32 size)
{
	U32 i;
	printf("\nstatic const U32 %s[%d] = \n  { 0x%08X", name, size, *data++);
	for (i = 1; i < size; i++)
	{
		if ((i & 3) == 0)
			printf(",\n    0x%08X", *data++);
		else
			printf(",0x%08X", *data++);
	}
	printf(" };\n");
}

void ecp_PrintHexWords(IN const char *name, IN const U32 *data, IN U32 size)
{
	printf("%s = 0x", name);
	while (size > 0) printf("%08X", data[--size]);
	printf("\n");
}
#endif

/* Needed for donna */
extern void ecp_TrimSecretKey(U8 *X);
const unsigned char BasePoint[32] = { 9 };

unsigned char secret_blind[32] =
{
	0xea,0x30,0xb1,0x6d,0x83,0x9e,0xa3,0x1a,0x86,0x34,0x01,0x9d,0x4a,0xf3,0x36,0x93,
	0x6d,0x54,0x2b,0xa1,0x63,0x03,0x93,0x85,0xcc,0x03,0x0a,0x7d,0xe1,0xae,0xa7,0xbb
};

int speed_test(int loops)
{
	U64 t1, t2, tovr = 0, td = (U64)(-1), tm = (U64)(-1);
	U8 secret_key[32], donna_publickey[32], mehdi_publickey[32];
	unsigned char pubkey[32], privkey[64], sig[64];
	void *ver_context = 0;
	void *blinding = 0;
	int i;

	/* generate key */
	mem_fill(secret_key, 0x42, 32);
	ecp_TrimSecretKey(secret_key);

	/* Make sure both generate identical public key */
	curve25519_donna(donna_publickey, secret_key, BasePoint);
	curve25519_dh_CalculatePublicKey(mehdi_publickey, secret_key);

	if (memcmp(mehdi_publickey, donna_publickey, 32) != 0)
	{
		ecp_PrintHexBytes("sk", secret_key, 32);
		ecp_PrintHexBytes("mehdi_pk", mehdi_publickey, 32);
		ecp_PrintHexBytes("donna_pk", donna_publickey, 32);
		printf("\n*********** Public keys do not match!! ********************\n");
		return 1;
	}

	/* Timing values that we measure includes some random CPU activity overhead */
	/* We try to get the minimum time as the more accurate time */

	t1 = readTSC();
	tovr = readTSC() - t1; /* t2-t1 = readTSC() overhead */
	for (i = 0; i < 100; i++)
	{
		t1 = readTSC();
		t2 = readTSC() - t1; /* t2-t1 = readTSC() overhead */
		if (t2 < tovr) tovr = t2;
	}

	/* --------------------------------------------------------------------- */
	/* Go Donna, go  */
	/* --------------------------------------------------------------------- */
	for (i = 0; i < loops; ++i)
	{
		t1 = readTSC();
		curve25519_donna(donna_publickey, secret_key, BasePoint);
		t2 = readTSC() - t1;
		if (t2 < td) td = t2;
	}
	td -= tovr;

	/* --------------------------------------------------------------------- */
	/* Ready, set, go  */
	/* --------------------------------------------------------------------- */
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		curve25519_dh_CalculatePublicKey(mehdi_publickey, secret_key);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("\n-- curve25519-DH --\n"
		"    Donna: %lld cycles = %.3f usec @3.4GHz -- ratio: %.3f\n",
		td, (double)td / 3400.0, (double)td / (double)tm);
	printf("    Mehdi: %lld cycles = %.3f usec @3.4GHz -- delta: %.2f%%\n",
		tm, (double)tm / 3400.0, (100.0*(td - tm)) / (double)td);

	/* --------------------------------------------------------------------- */
	/* Faster implementation using folding of 8 */
	/* --------------------------------------------------------------------- */
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		curve25519_dh_CalculatePublicKey_fast(mehdi_publickey, secret_key);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("\n-- curve25519-DH (w/folding) --\n"
		"    Donna: %lld cycles = %.3f usec @3.4GHz -- ratio: %.3f\n",
		td, (double)td / 3400.0, (double)td / (double)tm);
	printf("    Mehdi: %lld cycles = %.3f usec @3.4GHz -- delta: %.2f%%\n",
		tm, (double)tm / 3400.0, (100.0*(td - tm)) / (double)td);

	/* --------------------------------------------------------------------- */
	/* Speed measurement for ed25519 keygen, sign and verify */
	/* --------------------------------------------------------------------- */
	tm = (U64)(-1);
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		ed25519_CreateKeyPair(pubkey, privkey, 0, secret_key);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("\n-- ed25519 --\n"
		"    KeyGen: %lld cycles = %.3f usec @3.4GHz\n", tm, (double)tm / 3400.0);

	/* --------------------------------------------------------------------- */
	tm = (U64)(-1);
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		ed25519_SignMessage(sig, privkey, 0, (const unsigned char*)"abc", 3);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("      Sign: %lld cycles = %.3f usec @3.4GHz\n", tm, (double)tm / 3400.0);

	/* --------------------------------------------------------------------- */
	/* Speed measurement for ed25519 keygen, sign using blinding */
	/* --------------------------------------------------------------------- */
	blinding = ed25519_Blinding_Init(blinding, secret_blind, sizeof(secret_blind));

	tm = (U64)(-1);
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		ed25519_CreateKeyPair(pubkey, privkey, blinding, secret_key);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("    KeyGen: %lld cycles = %.3f usec @3.4GHz (Blinded)\n",
		tm, (double)tm / 3400.0);

	/* --------------------------------------------------------------------- */
	tm = (U64)(-1);
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		ed25519_SignMessage(sig, privkey, blinding, (const unsigned char*)"abc", 3);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("      Sign: %lld cycles = %.3f usec @3.4GHz (Blinded)\n",
		tm, (double)tm / 3400.0);

	ed25519_Blinding_Finish(blinding);

	/* --------------------------------------------------------------------- */
	tm = (U64)(-1);
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		ed25519_VerifySignature(sig, pubkey, (const unsigned char*)"abc", 3);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("    Verify: %lld cycles = %.3f usec @3.4GHz\n", tm, (double)tm / 3400.0);
	/* --------------------------------------------------------------------- */
	tm = (U64)(-1);
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		ver_context = ed25519_Verify_Init(ver_context, pubkey);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("    Verify: %lld cycles = %.3f usec @3.4GHz (Init)\n",
		tm, (double)tm / 3400.0);
	/* --------------------------------------------------------------------- */
	tm = (U64)(-1);
	for (i = 0; i < loops; i++)
	{
		t1 = readTSC();
		ed25519_Verify_Check(ver_context, sig, (const unsigned char*)"abc", 3);
		t2 = readTSC() - t1;
		if (t2 < tm) tm = t2;
	}
	tm -= tovr;

	printf("            %lld cycles = %.3f usec @3.4GHz (Check)\n",
		tm, (double)tm / 3400.0);

	ed25519_Verify_Finish(ver_context);

	return 0;
}

int signature_test(
	const unsigned char *sk,
	const unsigned char *expected_pk,
	const unsigned char *msg, size_t size,
	const unsigned char *expected_sig)
{
	int rc = 0;
	unsigned char sig[ed25519_signature_size];
	unsigned char pubKey[ed25519_public_key_size];
	unsigned char privKey[ed25519_private_key_size];
	void *blinding = ed25519_Blinding_Init(0, secret_blind, sizeof(secret_blind));

	printf("\n-- ed25519 -- sign/verify test ---------------------------------\n");
	printf("\n-- CreateKeyPair --\n");
	ed25519_CreateKeyPair(pubKey, privKey, 0, sk);
	ecp_PrintHexBytes("secret_key", sk, ed25519_secret_key_size);
	ecp_PrintHexBytes("public_key", pubKey, ed25519_public_key_size);
	ecp_PrintBytes("private_key", privKey, ed25519_private_key_size);

	if (expected_pk && memcmp(pubKey, expected_pk, ed25519_public_key_size) != 0)
	{
		rc++;
		printf("ed25519_CreateKeyPair() FAILED!!\n");
		ecp_PrintHexBytes("Expected_pk", expected_pk, ed25519_public_key_size);
	}

	printf("-- Sign/Verify --\n");
	ed25519_SignMessage(sig, privKey, 0, msg, size);
	ecp_PrintBytes("message", msg, (U32)size);
	ecp_PrintBytes("signature", sig, ed25519_signature_size);
	if (expected_sig && memcmp(sig, expected_sig, ed25519_signature_size) != 0)
	{
		rc++;
		printf("Signature generation FAILED!!\n");
		ecp_PrintBytes("Calculated", sig, ed25519_signature_size);
		ecp_PrintBytes("ExpectedSig", expected_sig, ed25519_signature_size);
	}

	if (!ed25519_VerifySignature(sig, pubKey, msg, size))
	{
		rc++;
		printf("Signature verification FAILED!!\n");
		ecp_PrintBytes("sig", sig, ed25519_signature_size);
		ecp_PrintBytes("pk", pubKey, ed25519_public_key_size);
	}

	printf("\n-- ed25519 -- sign/verify test w/blinding ----------------------\n");
	printf("\n-- CreateKeyPair --\n");
	ed25519_CreateKeyPair(pubKey, privKey, blinding, sk);
	ecp_PrintHexBytes("secret_key", sk, ed25519_secret_key_size);
	ecp_PrintHexBytes("public_key", pubKey, ed25519_public_key_size);
	ecp_PrintBytes("private_key", privKey, ed25519_private_key_size);

	if (expected_pk && memcmp(pubKey, expected_pk, ed25519_public_key_size) != 0)
	{
		rc++;
		printf("ed25519_CreateKeyPair() FAILED!!\n");
		ecp_PrintHexBytes("Expected_pk", expected_pk, ed25519_public_key_size);
	}

	printf("-- Sign/Verify --\n");
	ed25519_SignMessage(sig, privKey, blinding, msg, size);
	ecp_PrintBytes("message", msg, (U32)size);
	ecp_PrintBytes("signature", sig, ed25519_signature_size);
	if (expected_sig && memcmp(sig, expected_sig, ed25519_signature_size) != 0)
	{
		rc++;
		printf("Signature generation FAILED!!\n");
		ecp_PrintBytes("Calculated", sig, ed25519_signature_size);
		ecp_PrintBytes("ExpectedSig", expected_sig, ed25519_signature_size);
	}

	if (!ed25519_VerifySignature(sig, pubKey, msg, size))
	{
		rc++;
		printf("Signature verification FAILED!!\n");
		ecp_PrintBytes("sig", sig, ed25519_signature_size);
		ecp_PrintBytes("pk", pubKey, ed25519_public_key_size);
	}

	if (rc == 0)
	{
		printf("  ++ Signature Verified Successfully. ++\n");
	}

	ed25519_Blinding_Finish(blinding);
	return rc;
}

unsigned char sk1[32] =
{ 0x4c,0xcd,0x08,0x9b,0x28,0xff,0x96,0xda,0x9d,0xb6,0xc3,0x46,0xec,0x11,0x4e,0x0f,
0x5b,0x8a,0x31,0x9f,0x35,0xab,0xa6,0x24,0xda,0x8c,0xf6,0xed,0x4f,0xb8,0xa6,0xfb };
unsigned char pk1[ed25519_public_key_size] =
{ 0x3d,0x40,0x17,0xc3,0xe8,0x43,0x89,0x5a,0x92,0xb7,0x0a,0xa7,0x4d,0x1b,0x7e,0xbc,
0x9c,0x98,0x2c,0xcf,0x2e,0xc4,0x96,0x8c,0xc0,0xcd,0x55,0xf1,0x2a,0xf4,0x66,0x0c };
unsigned char msg1[] = { 0x72 };
unsigned char msg1_sig[ed25519_signature_size] = {
	0x92,0xa0,0x09,0xa9,0xf0,0xd4,0xca,0xb8,0x72,0x0e,0x82,0x0b,0x5f,0x64,0x25,0x40,
	0xa2,0xb2,0x7b,0x54,0x16,0x50,0x3f,0x8f,0xb3,0x76,0x22,0x23,0xeb,0xdb,0x69,0xda,
	0x08,0x5a,0xc1,0xe4,0x3e,0x15,0x99,0x6e,0x45,0x8f,0x36,0x13,0xd0,0xf1,0x1d,0x8c,
	0x38,0x7b,0x2e,0xae,0xb4,0x30,0x2a,0xee,0xb0,0x0d,0x29,0x16,0x12,0xbb,0x0c,0x00
};

int curve25519_SelfTest(int level);
int ed25519_selftest();

int dh_test()
{
	int rc = 0;
	unsigned char alice_public_key[32], alice_shared_key[32];
	unsigned char bruce_public_key[32], bruce_shared_key[32];

	unsigned char alice_secret_key[32] = { /* #1234 */
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,
		0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,
		0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4 };

	unsigned char bruce_secret_key[32] = { /* #abcd */
		0x88,0xd4,0x26,0x6f,0xd4,0xe6,0x33,0x8d,
		0x13,0xb8,0x45,0xfc,0xf2,0x89,0x57,0x9d,
		0x20,0x9c,0x89,0x78,0x23,0xb9,0x21,0x7d,
		0xa3,0xe1,0x61,0x93,0x6f,0x03,0x15,0x89 };

	printf("\n-- curve25519 -- key exchange test -----------------------------\n");
	/* Step 1. Alice and Bruce generate their own random secret keys */

	ecp_PrintHexBytes("Alice_secret_key", alice_secret_key, 32);
	ecp_PrintHexBytes("Bruce_secret_key", bruce_secret_key, 32);

	/* Step 2. Alice and Bruce create public keys associated with their secret keys */
	/*         and exchange their public keys */

	curve25519_dh_CalculatePublicKey(alice_public_key, alice_secret_key);
	curve25519_dh_CalculatePublicKey(bruce_public_key, bruce_secret_key);
	ecp_PrintHexBytes("Alice_public_key", alice_public_key, 32);
	ecp_PrintHexBytes("Bruce_public_key", bruce_public_key, 32);

	/* Step 3. Alice and Bruce create their shared key */

	curve25519_dh_CreateSharedKey(alice_shared_key, bruce_public_key, alice_secret_key);
	curve25519_dh_CreateSharedKey(bruce_shared_key, alice_public_key, bruce_secret_key);
	ecp_PrintHexBytes("Alice_shared", alice_shared_key, 32);
	ecp_PrintHexBytes("Bruce_shared", bruce_shared_key, 32);

	/* Alice and Bruce should end up with idetntical keys */
	if (memcmp(alice_shared_key, bruce_shared_key, 32) != 0)
	{
		rc++;
		printf("DH key exchange FAILED!!\n");
	}
	return rc;
}

static const U8 _b_Om111[32] = {      /* O-1 */
	0xEC,0xD3,0xF5,0x5C,0x1A,0x63,0x12,0x58,0xD6,0x9C,0xF7,0xA2,0xDE,0xF9,0xDE,0x14,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10 };

static const U8 _b_Pp3d811[32] = {    /* (P+3)/8 */
	0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0x0F };

const U_WORD _w_I11[K_WORDS] = /* sqrt(-1) */
W256(0x4A0EA0B0, 0xC4EE1B27, 0xAD2FE478, 0x2F431806, 0x3DFBD7A7, 0x2B4D0099, 0x4FC1DF0B, 0x2B832480);

/* Y = X ** E mod P */
/* E is in little-endian format */
void ecp_ExpMod(U_WORD* Y, const U_WORD* X, const U8* E, int bytes)
{
	int i;
	ecp_SetValue(Y, 1);
	while (bytes-- > 0)
	{
		U8 e = E[bytes];
		for (i = 0; i < 8; i++)
		{
			ecp_SqrReduce(Y, Y);
			if (e & 0x80) ecp_MulReduce(Y, Y, X);
			e <<= 1;
		}
	}
	ecp_Mod(Y);
}


void ecp_CalculateY(OUT U8 *Y, IN const U8 *X)
{
	U_WORD A[K_WORDS], B[K_WORDS], T[K_WORDS];

	ecp_BytesToWords(T, X);
	ecp_SetValue(A, 486662);
	ecp_AddReduce(A, A, T);     /* x + 486662 */
	ecp_MulReduce(A, A, T);     /* x^2 + 486662x */
	ecp_MulReduce(A, A, T);     /* x^3 + 486662x^2 */
	ecp_AddReduce(A, A, T);     /* x^3 + 486662x^2 + x */
	ecp_ExpMod(T, A, _b_Pp3d811, 32);
	/* if T*T != A: T *= sqrt(-1) */
	ecp_MulMod(B, T, T);
	if (ecp_CmpNE(B, A)) ecp_MulMod(T, T, _w_I11);
	ecp_WordsToBytes(Y, T);
}

const U_WORD _w_P11[K_WORDS] =
W256(0xFFFFFFED, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF);

// check if y^2 == x^3 + 486662x^2 + x  mod 2^255 - 19
int x25519_IsOnCurve(IN const U_WORD *X, IN const U_WORD *Y)
{
	U_WORD A[K_WORDS], B[K_WORDS];

	ecp_SetValue(A, 486662);
	ecp_AddReduce(A, A, X);     /* x + 486662 */
	ecp_MulReduce(A, A, X);     /* x^2 + 486662x */
	ecp_MulReduce(A, A, X);     /* x^3 + 486662x^2 */
	ecp_AddReduce(A, A, X);     /* x^3 + 486662x^2 + x */
	ecp_SqrReduce(B, Y);
	ecp_Mod(A);
	ecp_Mod(B);
	if (ecp_CmpNE(B, A) == 0) return 1;
	// check if sqrt(-1) was applied incorrectly
	ecp_Sub(B, _w_P11, B);
	return (ecp_CmpNE(B, A) == 0) ? 1 : 0;
}

//void GetRandomBytes(unsigned char *buffer, int size);
#include <time.h>
#if defined(_MSC_VER)
#include <windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#endif
#include <memory.h>
#include "../source/sha512.h"

/* Customize this with your own random key */
static const unsigned char my_secret_key[] =
{
	0x1c,0xf2,0x42,0x5f,0x89,0x0f,0x68,0xd3,0x85,0x99,0xba,0x26,0xbb,0x8e,0x57,0x3f,
	0x4b,0x58,0x51,0x5a,0x04,0x3c,0x3f,0x26,0x94,0xa0,0xee,0x3a,0x8f,0xf9,0xd1,0x9f,
	0x22,0xa1,0x23,0xfc,0xe3,0xef,0x59,0x1f,0xca,0x7e,0x51,0x67,0x24,0x3b,0x06,0xce,
	0x57,0x71,0xca,0xc2,0x19,0xdb,0x07,0xc2,0x82,0xaf,0x41,0x9f,0x57,0xb5,0x7b,0x21
};

void GetRandomBytes(unsigned char *buffer, int size)
{
#if defined(_MSC_VER)
	HCRYPTPROV hcp;
	CryptAcquireContext(&hcp, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	CryptGenRandom(hcp, size, buffer);
	CryptReleaseContext(hcp, 0);
#else
	FILE *fp = fopen("/dev/urandom", "r");
	fread(buffer, sizeof(unsigned char), size, fp);
	fclose(fp);
#endif

	/* -- paranoia ----------------------------------------------------------
	//
	// System level RNG's could be compromized, monitored, hacked, hooked,...
	//
	// We are putting a custom layer of transformation on top which includes
	// a secret key
	//
	// ----------------------------------------------------------------------
	*/
	while (size > 0)
	{
		SHA512_CTX hash;

		SHA512_Init(&hash);
		SHA512_Update(&hash, my_secret_key, sizeof(my_secret_key));
		SHA512_Update(&hash, buffer, size);

		if (size <= SHA512_DIGEST_LENGTH)
		{
			unsigned char digest[SHA512_DIGEST_LENGTH];
			SHA512_Final(digest, &hash);
			memcpy(buffer, digest, size);
			break;
		}

		SHA512_Final(buffer, &hash);
		buffer += SHA512_DIGEST_LENGTH;
		size -= SHA512_DIGEST_LENGTH;
	}
}


int main(int argc, char**argv)
{
	U_WORD A[K_WORDS], B[K_WORDS], C[K_WORDS], T[2 * K_WORDS];
	U8 a[32], b[32], c[32], d[32];

	U32 n = 1 << 20;
	mem_fill(b, 0, 32);

	clock_t t;
	t = clock();


	for (int i = 0; i < n; i++)
	{
		int order_test, on_curve;
		//GetRandomBytes(b, 32);
		b[0] = (U8)(i+10);
		b[31] &= 0x7f;
		/*ecp_PointMultiply(b, ecp_BasePoint, b, 32); */
		ecp_PointMultiply(a, b, _b_Om111, 32);
		order_test = (memcmp(a, b, 32) == 0) ? 1 : 0;

		/* It it on the curve? */
		ecp_CalculateY(a, b);
		ecp_BytesToWords(A, a);
		ecp_BytesToWords(B, b);
		on_curve = x25519_IsOnCurve(B, A);
		/*if (on_curve) printf("OnCurve=True"); else printf("OnCurve=FALSE");
		if (order_test) printf("  Order=BPO\n"); else printf("  Order=DIFFERENT\n");
		ecp_PrintHexBytes("x", b, 32);
		ecp_PrintHexBytes("y", a, 32);*/
	}

	t = clock() - t;
	double time_taken = ((double)t) / CLOCKS_PER_SEC; // in seconds 
	printf("n= \n", n);
	printf("on_curve? took %f seconds to execute \n", time_taken);

	return 0;

	//on_curve? took 237.250000 seconds to execute  U32 n = 1 << 20
//	on_curve ? took 14.870000 seconds to execute n = 1 << 16

 //took 211.520000 seconds to execute n = 1 << 20












	int rc = 0;

	curve25519_SelfTest(0);
#ifdef ECP_SELF_TEST
	if (curve25519_SelfTest(0))
	{
		printf("\n*********** curve25519 selftest FAILED!! ******************\n");
		return 1;
	}
	if (ed25519_selftest())
	{
		printf("\n*********** ed25519 selftest FAILED!! ********************\n");
		return 1;
	}
#endif

	rc += dh_test();

	rc += signature_test(sk1, pk1, msg1, sizeof(msg1), msg1_sig);

	speed_test(1000);

	return rc;
}