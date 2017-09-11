#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <limits.h>


struct csKeys_SF {
  struct hashKey_SF {
    BIGNUM *p;
    BIGNUM *q;
  } CK;
  BIGNUM *HK;
};

struct csKeys_DL {
  struct hashKey_DL {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *y;
  } HK;
  BIGNUM *CK;
};

struct csKeys_AF {
  struct trapdoor_AF {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *lambda;
  } CK;
  struct hashKey_AF {
    BIGNUM *n;
    BIGNUM *g;
  } HK;
};


int CS_Rnd(BIGNUM *bnN, BIGNUM *bnRnd);

int CS_GenerateAB(BIGNUM *bnP, BIGNUM *bnQ, BIGNUM *bnA, BIGNUM *bnB);

int CS_GenChamKeys_SF(int iSctyPrmtr, struct csKeys_SF *cskChamKeys);

int CS_ChamHash_SF(const unsigned char* pchMsg, BIGNUM *bnRnd, BIGNUM *bnHK,
	BIGNUM *bnChamDigest);

int CS_ClsnFind_SF(BIGNUM *bnChamDigest, char* pchMsg,
	struct csKeys_SF cskTrapdoor, BIGNUM *bnRandom);

int CS_GenChamKeys_DL(int iSctyPrmtr, struct csKeys_DL *cskChamKeys);

int CS_ChamHash_DL(char* pchMsg, BIGNUM *bnRnd, struct hashKey_DL HK,
	BIGNUM *bnChamDigest);

int CS_ClsnFind_DL(BIGNUM *bnRandom1, char* pchMsg1, char* pchMsg2,
	struct csKeys_DL cskTrapdoor, BIGNUM *bnRandom2);

int CS_GenChamKeys_AF(int iSctyPrmtr, struct csKeys_AF *cskChamKeys);

int CS_ChamHash_AF(int iK, char* pchMsg, BIGNUM *bnRnd, struct hashKey_AF HK,
	BIGNUM *bnChamDigest);

int CS_ClsnFind_AF(int iK, BIGNUM *bnRandom1, char* pchMsg1, char* pchMsg2,
	struct trapdoor_AF cskTrapdoor, BIGNUM *bnRandom2);


int SF(int iSctyPrmtr, int chain_length);
int DL(int iSctyPrmtr, int chain_length);
int AF(int iSctyPrmtr, int chain_length);
