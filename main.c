#include "cham.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <math.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/engine.h>


#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

/* Constants */
#define SAFE 1
#define UNSAFE 0
#define TRUE 1
#define FALSE 0
#define DIM_MSG_DGST 160


int main(int argc,char **argv){
  int SF(int, int);
  int DL(int, int);
  int AF(int, int);

  if (!argv[1]){
    printf("\nSyntax: %s <Hash-length> <Length of Chameleon chain>\n", argv[0]);
    printf(" \t%s 160 1000\n", argv[0]);
    exit (0);
  }

  int iSctyPrmtr = atoi(argv[1]);
  int NTIMES = atoi(argv[2]);


  printf("\nCalling SF\n");
  SF(iSctyPrmtr, NTIMES);
  printf("\nExited SF\n");

  DL(iSctyPrmtr, NTIMES);
  AF(iSctyPrmtr, NTIMES);

} //// END OF MAIN


int CS_Rnd(BIGNUM *bnN, BIGNUM *bnRnd){
  unsigned long y;
  char *Rnd_str;
  BIGNUM **Rnd_bn_ptr;
  *Rnd_bn_ptr = bnRnd;
  Rnd_str = (char *)malloc(200);

	do{
		if (BN_rand_range(bnRnd, bnN) == 0) {
		  printf("\nError in generating a big random number!");
		  return 0;
		}
	} while ((BN_cmp(bnRnd, bnN) != (-1)) || BN_is_zero(bnRnd));

	return 1;
}


int CS_GenerateAB(BIGNUM *bnP, BIGNUM *bnQ, BIGNUM *bnA, BIGNUM *bnB){
	BIGNUM *bnT = BN_new();
	BIGNUM *bnT2 = BN_new();
	BIGNUM *bn1 = BN_new();
	BN_CTX *bnCtx =BN_CTX_new();
	if (BN_one(bn1) == 0) 	  printf("\nERROR4\n");

	if (BN_mod_inverse(bnA, bnP, bnQ, bnCtx) == 0) {
	  printf("ERRORC1\n");
	  return 0;
	}

	do {
		if (BN_mul(bnT, bnA, bnP, bnCtx) == 0) {
		  printf("ERRORC2\n");
		  return 0;
		}
		if (BN_sub(bnT, bn1, bnT) == 0) {
		  printf("ERRORC3\n");
		  return 0;
		}

		if (BN_nnmod(bnT2, bnT, bnQ, bnCtx) == 0) {
		  printf("ERRORC4\n");
		  return 0;
		}

		if (BN_is_zero(bnT2) != 1){
		  if (BN_add(bnA, bnA, bnQ) == 0){
		    printf("ERRORC5\n");
		    return 0;
		  }
		}

	} while (BN_is_zero(bnT2) != 1);

	if (BN_div(bnB, NULL, bnT, bnQ, bnCtx) == 0) {
	  printf("ERRORC6\n");
	  return 0;
	}

	BN_free(bn1);
	BN_free(bnT);
	BN_free(bnT2);
	BN_CTX_free(bnCtx);

	return 1;
}


int CS_GenChamKeys_SF(int iSctyPrmtr, struct csKeys_SF *cskChamKeys){

  BIGNUM *bn3 = BN_new();
  BIGNUM *bn7 = BN_new();
  BIGNUM *bn8 = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();

  if (BN_set_word(bn3, 3UL) == 0)
    printf("\nERROR1\n");
  if (BN_set_word(bn7, 7UL) == 0)
    printf("\nERROR2\n");
  if (BN_set_word(bn8, 8UL) == 0)
    printf("\nERROR3\n");

  struct csKeys_SF cskTemp;

  cskTemp.CK.p = BN_new();
  cskTemp.CK.q = BN_new();
  cskTemp.HK = BN_new();

  if (BN_generate_prime(cskTemp.CK.p, (iSctyPrmtr/2),
			UNSAFE, bn8, bn3,NULL,NULL) == NULL) {
    printf("\nImpossibile generare il numero primo");
    return 0;
  }

  if (BN_generate_prime(cskTemp.CK.q, (iSctyPrmtr/2),
			UNSAFE, bn8, bn7,NULL,NULL) == NULL) {
    printf("\nImpossibile generare il numero primo");
    return 0;
  }

  if (BN_mul(cskTemp.HK, cskTemp.CK.p, cskTemp.CK.q,
	     bnCtx) == 0) {
    printf("\nImpossibile generare chiave pubblica");
    return 0;
  }

  cskChamKeys->HK = cskTemp.HK;
  cskChamKeys->CK = cskTemp.CK;

  BN_free(bn3);
  BN_free(bn7);
  BN_free(bn8);

  BN_CTX_free(bnCtx);

  return 1;

}

int CS_ChamHash_SF(const unsigned char* pchMsg, BIGNUM *bnRnd, BIGNUM *bnHK,
		   BIGNUM *bnChamDigest){

  printf("\nEntered CS_ChamHash_SF\n");
  BIGNUM *bn1 = BN_new();
  BIGNUM *bn4 = BN_new();   printf("\nHI-3\n");
  BIGNUM *bn2M = BN_new(); printf("\nHI-1\n");
  BIGNUM *bn4M = BN_new();  printf("\nHI-2\n");
  char *tt; tt = (char*) malloc(100); if(NULL != tt) printf("X\n");
  BIGNUM *bnMsgDgst = BN_new();	 printf("\nHI-x\n");
  BIGNUM *bnR2M = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();
  printf("\nEntered CS_ChamHash_SF-2\n");


  if (BN_one(bn1) == 0)
    printf("\nERROR4\n");
  if (BN_set_word(bn4, 4UL) == 0)
    printf("\nERROR6\n");


  unsigned char* pchMsgDgst = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg, (unsigned long)strlen(pchMsg),pchMsgDgst);

  BN_bin2bn(pchMsgDgst, DIM_MSG_DGST/8, bnMsgDgst);
  if (bnMsgDgst == NULL)
    printf("\nERROR7\n");

  if (BN_mod_exp(bn4M, bn4, bnMsgDgst, bnHK, bnCtx) == 0) {
    printf("\nERROR10\n");
    return 0;
  }

  if (BN_lshift(bn2M, bn1, DIM_MSG_DGST) == 0) {
    printf("\nERROR11\n");
    return 0;
  }

  if (BN_mod_exp(bnR2M, bnRnd, bn2M, bnHK, bnCtx) == 0) {
    printf("\nERROR12\n");
    return 0;
  }

  if (BN_mod_mul(bnChamDigest, bn4M, bnR2M, bnHK, bnCtx) == 0) {
    printf("\nERROR13\n");
    return 0;
  }

  BN_free(bn1);
  BN_free(bn2M);
  BN_free(bn4);
  BN_free(bn4M);
  BN_free(bnMsgDgst);
  BN_free(bnR2M);
  BN_CTX_free(bnCtx);

  return 1;
}

int CS_ClsnFind_SF(BIGNUM *bnChamDigest, char* pchMsg, struct csKeys_SF cskTrapdoor, BIGNUM *bnRandom){

  int iCount;

  BIGNUM *bn0 = BN_new();
  BIGNUM *bnA = BN_new();
  BIGNUM *bnAP = BN_new();
  BIGNUM *bnAPS = BN_new();
  BIGNUM *bnB = BN_new();
  BIGNUM *bnBQ = BN_new();
  BIGNUM *bnBQT = BN_new();
  BIGNUM *bnInverse2 = BN_new();
  BIGNUM *bnMsgDgst = BN_new();
  BIGNUM *bnN = BN_new();
  BIGNUM *bnNegY = BN_new();
  BIGNUM *bnP = BN_new();
  BIGNUM *bnPPlus1Div4 = BN_new();
  BIGNUM *bnQ = BN_new();
  BIGNUM *bnQPlus1Div4 = BN_new();
  BIGNUM *bnS = BN_new();
  BIGNUM *bnS1 = BN_new();
  BIGNUM *bnS2 = BN_new();
  BIGNUM *bnT = BN_new();
  BIGNUM *bnT1 = BN_new();
  BIGNUM *bnT2 = BN_new();
  BIGNUM *bnY = BN_new();

  BN_CTX *bnCtx = BN_CTX_new();

  if (BN_zero(bn0) == 0)
    printf("\nERROR4\n");
  if (BN_set_word(bnInverse2, 2UL) == 0)
    printf("\nERROR4\n");

  BN_copy(bnP, cskTrapdoor.CK.p);
  BN_copy(bnQ, cskTrapdoor.CK.q);
  BN_copy(bnN, cskTrapdoor.HK);


  if (BN_mod_inverse(bnInverse2, bnInverse2, bnN, bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }

  BN_copy(bnY, bnChamDigest);

  unsigned char* pchMsgDgst = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg, (unsigned long)strlen(pchMsg),pchMsgDgst);

  BN_bin2bn(pchMsgDgst, DIM_MSG_DGST/8, bnMsgDgst);
  if (bnMsgDgst == NULL)
    printf("\nERROR7\n");

  BN_copy(bnPPlus1Div4, bnP);
  if (BN_add_word(bnPPlus1Div4, 1) == 0) {
    printf("\nERRORC\n");
    return 0;
  }

  BN_copy(bnQPlus1Div4, bnQ);
  if (BN_add_word(bnQPlus1Div4, 1) == 0) {
    printf("\nERRORD\n");
    return 0;
  }

  if (BN_rshift(bnPPlus1Div4, bnPPlus1Div4, 2) == 0) {
    printf("\nERRORE\n");
    return 0;
  }

  if (BN_rshift(bnQPlus1Div4, bnQPlus1Div4, 2) == 0) {
    printf("\nERRORF\n");
    return 0;
  }


  if (CS_GenerateAB(bnP, bnQ, bnA, bnB) == 0) {
    printf("\nERRORG\n");
    return 0;
  }

  if (BN_mul(bnAP, bnA, bnP, bnCtx) == 0) {
    printf("\nERRORG\n");
    return 0;
  }

  if (BN_mul(bnBQ, bnB, bnQ, bnCtx) == 0) {
    printf("\nERRORG\n");
    return 0;
  }

  int iBit = 0;

  for (iCount = (DIM_MSG_DGST-1); iCount >= 0; iCount--) {

    if (BN_mod_exp(bnT/*1*/, bnY, bnPPlus1Div4, bnP, bnCtx) == 0) {
      printf("\nERRORA2\n");
      return 0;
    }

    if (BN_mod_exp(bnS/*1*/, bnY, bnQPlus1Div4, bnQ, bnCtx)
	== 0) {
      printf("\nERRORA4\n");
      return 0;
    }

    iBit = (pchMsgDgst[iCount/CHAR_BIT] >>
	    ((CHAR_BIT-1)-(iCount%8)))&1;

    if (BN_mul(bnAPS,bnAP,bnS,bnCtx) == 0) {
      printf("\nERRORM\n");
      return 0;
    }

    if (BN_mul(bnBQT,bnBQ,bnT,bnCtx) == 0) {
      printf("\nERRORO\n");
      return 0;
    }

    switch(iCount%4) {
    case 0: {
      if (BN_mod_add(bnY, bnAPS, bnBQT, bnN, bnCtx) == 0) {
	printf("ERROR\n");
	return 0;
      } break;
    }
    case 1: {
      if (BN_mod_sub(bnY, bnAPS, bnBQT, bnN, bnCtx) == 0) {
	printf("ERROR\n");
	return 0;
      } break;
    }
    case 2: {
      if (BN_mod_sub(bnY, bnBQT, bnAPS, bnN, bnCtx) == 0) {
	printf("ERROR\n");
	return 0;
      } break;
    }
    case 3: {
      if (BN_sub(bnAPS, bn0, bnAPS) == 0){
	printf("ERROR\n");
	return 0;
      }
      if (BN_mod_sub(bnY, bnAPS, bnBQT, bnN, bnCtx) == 0) {
	printf("ERROR\n");
	return 0;
      } break;
    }
    }

    if (iBit == 1) {
      if (BN_mod_mul(bnY, bnY, bnInverse2, bnN, bnCtx) == 0) {
	printf("ERROR\n");
	return 0;
      }
    }

  }

  BN_copy(bnRandom, bnY);

  BN_free(bn0);
  BN_free(bnA);
  BN_free(bnAP);
  BN_free(bnAPS);
  BN_free(bnB);
  BN_free(bnBQ);
  BN_free(bnBQT);
  BN_free(bnInverse2);
  BN_free(bnMsgDgst);
  BN_free(bnN);
  BN_free(bnNegY);
  BN_free(bnP);
  BN_free(bnPPlus1Div4);
  BN_free(bnQ);
  BN_free(bnQPlus1Div4);
  BN_free(bnS);
  BN_free(bnS1);
  BN_free(bnS2);
  BN_free(bnT);
  BN_free(bnT1);
  BN_free(bnT2);
  BN_free(bnY);

  BN_CTX_free(bnCtx);

  return 1;
}

int CS_GenChamKeys_DL(int iSctyPrmtr, struct csKeys_DL *cskChamKeys){
	BN_CTX *bnCtx = BN_CTX_new();

	cskChamKeys->HK.p = BN_new();
	cskChamKeys->HK.q = BN_new();
	cskChamKeys->HK.g = BN_new();
	cskChamKeys->HK.y = BN_new();
	cskChamKeys->CK   = BN_new();

	if (BN_generate_prime(cskChamKeys->HK.p, iSctyPrmtr,
			      SAFE, NULL, NULL,NULL,NULL) == NULL){
	  printf("\nImpossibile generare il numero primo");
	  return 0;
	}

	BN_copy(cskChamKeys->HK.q, cskChamKeys->HK.p);
	if (BN_sub_word(cskChamKeys->HK.q, 1) == 0) {
	  printf("\nERROR");
	  return 0;
	}
	if (BN_rshift1(cskChamKeys->HK.q, cskChamKeys->HK.q) == 0) {
	  printf("\nERROR");
	  return 0;
	}

	if (CS_Rnd(cskChamKeys->HK.p, cskChamKeys->HK.g) == 0) {
	  printf("\nERROR");
	  return 0;
	}
	if (BN_mod_sqr(cskChamKeys->HK.g, cskChamKeys->HK.g,
		       cskChamKeys->HK.p, bnCtx) == 0) {
	  printf("\nERROR");
	  return 0;
	}

	if (CS_Rnd(cskChamKeys->HK.q, cskChamKeys->CK) == 0) {
	  printf("\nERROR");
	  return 0;
	}

	if (BN_mod_exp(cskChamKeys->HK.y, cskChamKeys->HK.g,
		       cskChamKeys->CK, cskChamKeys->HK.p, bnCtx) == 0) {
	  printf("\nERROR");
	  return 0;
	}


	BN_CTX_free(bnCtx);

	return 1;
}

int CS_ChamHash_DL(char* pchMsg, BIGNUM *bnRnd, struct hashKey_DL HK,
		   BIGNUM *bnChamDigest){

  BIGNUM *bnGM = BN_new();
  BIGNUM *bnMsgDgst = BN_new();
  BIGNUM *bnYR = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();

  unsigned char* pchMsgDgst = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg, (unsigned long)strlen(pchMsg),pchMsgDgst);

  BN_bin2bn(pchMsgDgst, DIM_MSG_DGST/8, bnMsgDgst);
  if (bnMsgDgst == NULL)
    printf("\nERROR7\n");

  if (BN_mod_exp(bnGM, HK.g, bnMsgDgst, HK.p, bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_mod_exp(bnYR, HK.y, bnRnd, HK.p, bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_mod_mul(bnChamDigest, bnGM, bnYR, HK.p, bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }

  BN_free(bnGM);
  BN_free(bnMsgDgst);
  BN_free(bnYR);
  BN_CTX_free(bnCtx);

  return 1;
}

int CS_ClsnFind_DL(BIGNUM *bnRandom1, char* pchMsg1, char* pchMsg2,
		   struct csKeys_DL cskTrapdoor, BIGNUM *bnRandom2){

  BIGNUM *bnAlphaInverse = BN_new();
  BIGNUM *bnMDiff = BN_new();
  BIGNUM *bnMDiffDivAlpha = BN_new();
  BIGNUM *bnMsgDgst1 = BN_new();
  BIGNUM *bnMsgDgst2 = BN_new();

  BN_CTX *bnCtx = BN_CTX_new();


  unsigned char* pchMsgDgst1 = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg1, (unsigned long)strlen(pchMsg1),pchMsgDgst1);

  unsigned char* pchMsgDgst2 = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg2, (unsigned long)strlen(pchMsg2),pchMsgDgst2);

  BN_bin2bn(pchMsgDgst1, DIM_MSG_DGST/8, bnMsgDgst1);
  if (bnMsgDgst1 == NULL)
    printf("\nERROR7\n");

  BN_bin2bn(pchMsgDgst2, DIM_MSG_DGST/8, bnMsgDgst2);
  if (bnMsgDgst2 == NULL)
    printf("\nERROR7\n");

  if (BN_sub(bnMDiff, bnMsgDgst1, bnMsgDgst2) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_mod_inverse(bnAlphaInverse, cskTrapdoor.CK,
		     cskTrapdoor.HK.q,bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }
  if (BN_mul(bnMDiffDivAlpha, bnMDiff, bnAlphaInverse,
	     bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_mod_add(bnRandom2, bnMDiffDivAlpha, bnRandom1,
		 cskTrapdoor.HK.q, bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }


  BN_free(bnAlphaInverse);
  BN_free(bnMDiff);
  BN_free(bnMDiffDivAlpha);
  BN_free(bnMsgDgst1);
  BN_free(bnMsgDgst2);
  BN_CTX_free(bnCtx);

  return 1;
}

int CS_GenChamKeys_AF(int iSctyPrmtr, struct csKeys_AF *cskChamKeys){

  BIGNUM *bnP1 = BN_new();
  BIGNUM *bnQ1 = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();

  cskChamKeys->HK.n = BN_new();
  cskChamKeys->HK.g = BN_new();
  cskChamKeys->CK.p = BN_new();
  cskChamKeys->CK.q = BN_new();
  cskChamKeys->CK.lambda = BN_new();

  if (BN_generate_prime(cskChamKeys->CK.p, iSctyPrmtr/2,
			SAFE, NULL, NULL,NULL,NULL) == NULL) {
    printf("\nImpossibile generare il numero primo");
    return 0;
  }

  if (BN_generate_prime(cskChamKeys->CK.q, iSctyPrmtr/2,
			SAFE, NULL, NULL,NULL,NULL) == NULL){
    printf("\nImpossibile generare il numero primo");
    return 0;
  }

  BN_copy(bnP1, cskChamKeys->CK.p);
  if (BN_sub_word(bnP1, 1) == 0) {
    printf("\nERROR");
    return 0;
  }
  if (BN_rshift1(bnP1, bnP1) == 0) {
    printf("\nERROR");
    return 0;
    }


  BN_copy(bnQ1, cskChamKeys->CK.q);
  if (BN_sub_word(bnQ1, 1) == 0) {
    printf("\nERROR");
    return 0;
  }

  if (BN_mul(cskChamKeys->CK.lambda, bnP1, bnQ1,
	     bnCtx) == 0) {
    printf("\nERROR");
    return 0;
  }

  if (BN_mul(cskChamKeys->HK.n, cskChamKeys->CK.p,
	     cskChamKeys->CK.q, bnCtx) == 0) {
    printf("\nERROR");
    return 0;
  }

  if (CS_Rnd(cskChamKeys->CK.lambda,
	     cskChamKeys->HK.g) == 0) {
    printf("\nERROR");
    return 0;
  }
  if (BN_mod_sqr(cskChamKeys->HK.g, cskChamKeys->HK.g,
		 cskChamKeys->HK.n, bnCtx) == 0) {
    printf("\nERROR");
    return 0;
  }


  BN_free(bnP1);
  BN_free(bnQ1);
  BN_CTX_free(bnCtx);

  return 1;

}

int CS_ChamHash_AF(int iK, char* pchMsg, BIGNUM *bnRnd, struct hashKey_AF HK,
		   BIGNUM *bnChamDigest){
  BIGNUM *bnMShifted = BN_new();
  BIGNUM *bnMsgDgst = BN_new();
  BIGNUM *bnMConcatWithR = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();

  unsigned char* pchMsgDgst = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg, (unsigned long)strlen(pchMsg),pchMsgDgst);
  BN_bin2bn(pchMsgDgst, DIM_MSG_DGST/8, bnMsgDgst);
  if (bnMsgDgst == NULL)
    printf("\nERROR7\n");

  int iRndNumBits = BN_num_bits(bnRnd);
  if (BN_lshift(bnMShifted, bnMsgDgst, iK) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_add(bnMConcatWithR, bnMShifted, bnRnd) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_mod_exp(bnChamDigest, HK.g, bnMConcatWithR, HK.n,
		 bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }

  BN_free(bnMConcatWithR);
  BN_free(bnMsgDgst);
  BN_free(bnMShifted);
  BN_CTX_free(bnCtx);

  return 1;
}

int CS_ClsnFind_AF(int iK, BIGNUM *bnRandom1, char* pchMsg1, char* pchMsg2,
		   struct trapdoor_AF cskTrapdoor, BIGNUM *bnRandom2){

  BIGNUM *bnMDiff = BN_new();
  BIGNUM *bnMsgDgst1 = BN_new();
  BIGNUM *bnMsgDgst2 = BN_new();

  BN_CTX *bnCtx = BN_CTX_new();

  unsigned char* pchMsgDgst1 = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg1, (unsigned long)strlen(pchMsg1),pchMsgDgst1);

  unsigned char* pchMsgDgst2 = (unsigned char*)malloc(DIM_MSG_DGST/8);
  SHA1(pchMsg2, (unsigned long)strlen(pchMsg2),pchMsgDgst2);

  BN_bin2bn(pchMsgDgst1, DIM_MSG_DGST/8, bnMsgDgst1);
  if (bnMsgDgst1 == NULL)
    printf("\nERROR7\n");

  BN_bin2bn(pchMsgDgst2, DIM_MSG_DGST/8, bnMsgDgst2);
  if (bnMsgDgst2 == NULL)
    printf("\nERROR7\n");

  if (BN_sub(bnMDiff, bnMsgDgst1, bnMsgDgst2) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_lshift(bnRandom2, bnMDiff, iK) == 0) {
    printf("ERROR\n");
    return 0;
  }

  if (BN_mod_add(bnRandom2, bnRandom2, bnRandom1,
		 cskTrapdoor.lambda, bnCtx) == 0) {
    printf("ERROR\n");
    return 0;
  }

  BN_free(bnMDiff);
  BN_free(bnMsgDgst1);
  BN_free(bnMsgDgst2);
  BN_CTX_free(bnCtx);

  return 1;
}

int SF(int iSctyPrmtr, int chain_length){
  char *dir, *tmp_str, *tmp_bnstr, *file_sfkg, *file_sfhg, *file_sffc, *file_avg_sfkg, *file_avg_sfhg, *file_avg_sffc;
  FILE *fp_sfkg, *fp_sfhg, *fp_sffc,
    *fp_avg_sfkg, *fp_avg_sfhg, *fp_avg_sffc;
  double time_sfkg[chain_length], time_sfhg[chain_length], time_sffc[chain_length];

  BIGNUM *tmp_bn = BN_new(), *reminder = BN_new();
  BN_CTX *CTX = BN_CTX_new();
  BIGNUM *avg_sfkg = BN_new(), *avg_sffc = BN_new();

  BIGNUM *bnRandom1 = BN_new();
  BIGNUM *bnRandom2 = BN_new();
  BIGNUM *bnChamDigest1 = BN_new();
  BIGNUM *bnChamDigest2 = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();
  unsigned char* pchMsg1 = "ABCD";
  unsigned char* pchMsg2 = "PQRS";
  struct csKeys_SF csk;
  int i;


  dir = (char *)malloc(200); tmp_str = (char *)malloc(200);
  file_sfkg = (char *)malloc(200);  file_sfhg = (char *)malloc(200);  file_sffc = (char *)malloc(200);
  file_avg_sfkg = (char *)malloc(200);  file_avg_sfhg = (char *)malloc(200);  file_avg_sffc = (char *)malloc(200);
  dir = getcwd(dir, 200);

  for(i = 0; i <= chain_length; i++) {
    start_counter(); /**** start key generation ***/
    if (CS_GenChamKeys_SF(iSctyPrmtr, &csk) == 0) {
      return 0;
    }
    if (CS_Rnd((BIGNUM*)(csk.HK), bnRandom1) == 0) {
      return 0;
    }

    if (BN_mod_sqr(bnRandom1, bnRandom1, csk.HK, bnCtx) == 0) {
      return 0;
    }

    if (CS_ChamHash_SF(pchMsg1, bnRandom1, csk.HK, bnChamDigest1) == 0) {
      return 0;
    } /* Problem in CS_ChamHash_SF */
    time_sfkg[i] = get_counter(); /*** end of key generation ***/
    printf("\nCHECK-POINT\n");


    start_counter(); /*** start finding collision ***/
    if (CS_ClsnFind_SF(bnChamDigest1, pchMsg2, csk, bnRandom2) == 0) {
      return 0;
    }
    if (CS_ChamHash_SF(pchMsg2, bnRandom2, csk.HK, bnChamDigest2) == 0) {
      return 0;
    }
    if (BN_cmp(bnChamDigest1, bnChamDigest2) != 0) {
      return 0;
    }
    time_sffc[i] = get_counter(); /*** end finding collision routine ***/
  }


  strcpy(file_sfkg, dir);    strcpy(file_sfhg, dir);  strcpy(file_sffc, dir);
  strcpy(file_avg_sfkg, dir);    strcpy(file_avg_sfhg, dir);  strcpy(file_avg_sffc, dir);
  strcat(file_sfkg, "/results/sfkg_data.txt");
  strcat(file_sfhg, "/results/sfhg_data.txt");
  strcat(file_sffc, "/results/sffc_data.txt");
  strcat(file_avg_sfkg, "/results/avg_sfkg_data.txt");
  strcat(file_avg_sfhg, "/results/avg_sfhg_data.txt");
  strcat(file_avg_sffc, "/results/avg_sffc_data.txt");
  fp_sfkg = fopen(file_sfkg, "w+");
  //fp_sfhg = fopen(file_sfhg, "w+");
  fp_sffc = fopen(file_sffc, "w+");
  fp_avg_sfkg = fopen(file_avg_sfkg, "w+");
  //    fp_avg_sfhg = fopen(file_avg_sfhg, "w+");
  fp_avg_sffc = fopen(file_avg_sffc, "w+");



  //compute average values of kg and fc
  BN_zero(avg_sfkg); BN_zero(avg_sffc);
  tmp_bnstr = (unsigned char *)malloc(2000);
  for(i = 0; i <= chain_length; i++) {
    sprintf(tmp_bnstr, "%.f", time_sfkg[i]);
    BN_dec2bn(&tmp_bn, tmp_bnstr);
    BN_add(avg_sfkg, avg_sfkg, tmp_bn);

    sprintf(tmp_bnstr, "%.f", time_sffc[i]);
    BN_dec2bn(&tmp_bn, tmp_bnstr);
    BN_add(avg_sffc, avg_sffc, tmp_bn);
  }
  sprintf(tmp_bnstr, "%d", i-1);
  BN_dec2bn(&tmp_bn, tmp_bnstr);
  BN_div(avg_sfkg, reminder, avg_sfkg, tmp_bn, CTX);
  BN_div(avg_sffc, reminder, avg_sffc, tmp_bn, CTX);
  free(tmp_bnstr);

  //dump arrays into files
  for(i = 0; i <= chain_length; i++) {
    sprintf(tmp_str, "%d", i);
    fputs(tmp_str, fp_sfkg); fputs("\t", fp_sfkg);
    fputs(tmp_str, fp_sffc); fputs("\t", fp_sffc);
    fputs(tmp_str, fp_avg_sfkg); fputs("\t", fp_avg_sfkg);
    fputs(BN_bn2dec(avg_sfkg), fp_avg_sfkg); fputs("\n", fp_avg_sfkg);
    fputs(tmp_str, fp_avg_sffc); fputs("\t", fp_avg_sffc);
    fputs(BN_bn2dec(avg_sffc), fp_avg_sffc); fputs("\n", fp_avg_sffc);
    sprintf(tmp_str, "%.f", time_sfkg[i]); fputs(tmp_str, fp_sfkg); fputs("\n", fp_sfkg);
    sprintf(tmp_str, "%.f", time_sffc[i]); fputs(tmp_str, fp_sffc); fputs("\n", fp_sffc);
  }


  //fulsh buffers into files by closing file pointers
  fclose(fp_sfkg);
  //fclose(fp_sfhg);
  fclose(fp_sffc);
  fclose(fp_avg_sfkg);
  //fclose(fp_avg_sfhg);
  fclose(fp_avg_sffc);
  //free resources
  free(dir); free(tmp_str);
  free(file_sfkg); free(file_sfhg); free(file_sffc);
  free(file_avg_sfkg); free(file_avg_sfhg); free(file_avg_sffc);


  BN_free(bnRandom1);
  BN_free(tmp_bn);
  BN_free(bnRandom2);
  BN_free(bnChamDigest1);
  BN_free(bnChamDigest2);

  BN_CTX_free(bnCtx);
  BN_CTX_free(CTX);


  return 1;
}


int DL(int iSctyPrmtr, int chain_length){
  char *dir, *tmp_str, *tmp_bnstr, *file_dlkg, *file_dlfc, *file_avg_dlkg, *file_avg_dlfc;
  FILE *fp_dlkg, *fp_dlfc, *fp_avg_dlkg, *fp_avg_dlfc;
  double time_dlkg[chain_length], time_dlfc[chain_length];

  BIGNUM *tmp_bn = BN_new(), *reminder = BN_new();
  BN_CTX *CTX = BN_CTX_new();
  BIGNUM *avg_dlkg = BN_new(), *avg_dlfc = BN_new();

  BIGNUM *bnRandom1 = BN_new();
  BIGNUM *bnRandom2 = BN_new();
  BIGNUM *bnChamDigest1 = BN_new();
  BIGNUM *bnChamDigest2 = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();
  unsigned char* pchMsg1 = "ABCD";
  unsigned char* pchMsg2 = "PQRS";
  struct csKeys_DL csk;
  int i;

  dir = (char *)malloc(200); tmp_str = (char *)malloc(200);
  file_dlkg = (char *)malloc(200); file_dlfc = (char *)malloc(200);
  file_avg_dlkg = (char *)malloc(200); file_avg_dlfc = (char *)malloc(200);
  dir = getcwd(dir, 200);


  for(i = 0; i <= chain_length; i++) {
    start_counter();
    if (CS_GenChamKeys_DL(iSctyPrmtr, &csk) == 0) {
      return 0;
    }
    if (CS_Rnd((BIGNUM*)(csk.HK.q), bnRandom1) == 0) {
      return 0;
    }
    if (CS_ChamHash_DL(pchMsg1, bnRandom1, csk.HK, bnChamDigest1) == 0) {
      return 0;
    }
    time_dlkg[i] = get_counter();

    start_counter();
    if (CS_ClsnFind_DL(bnRandom1, pchMsg1, pchMsg2, csk, bnRandom2) == 0) {
      return 0;
    }
    if (CS_ChamHash_DL(pchMsg2, bnRandom2, csk.HK, bnChamDigest2) == 0) {
      return 0;
    }
    if (BN_cmp(bnChamDigest1, bnChamDigest2) != 0) {
      return 0;
    }
    time_dlfc[i] = get_counter();
  }

  strcpy(file_dlkg, dir); strcpy(file_dlfc, dir);
  strcpy(file_avg_dlkg, dir); strcpy(file_avg_dlfc, dir);
  strcat(file_dlkg, "/results/dlkg_data.txt");
  strcat(file_dlfc, "/results/dlfc_data.txt");
  strcat(file_avg_dlkg, "/results/avg_dlkg_data.txt");
  strcat(file_avg_dlfc, "/results/avg_dlfc_data.txt");
  fp_dlkg = fopen(file_dlkg, "w+");
  fp_dlfc = fopen(file_dlfc, "w+");
  fp_avg_dlkg = fopen(file_avg_dlkg, "w+");
  fp_avg_dlfc = fopen(file_avg_dlfc, "w+");

  //compute average values of kg and fc
  BN_zero(avg_dlkg); BN_zero(avg_dlfc);
  tmp_bnstr = (unsigned char *)malloc(2000);
  for(i = 0; i <= chain_length; i++) {
    sprintf(tmp_bnstr, "%.f", time_dlkg[i]);
    BN_dec2bn(&tmp_bn, tmp_bnstr);
    BN_add(avg_dlkg, avg_dlkg, tmp_bn);

    sprintf(tmp_bnstr, "%.f", time_dlfc[i]);
    BN_dec2bn(&tmp_bn, tmp_bnstr);
    BN_add(avg_dlfc, avg_dlfc, tmp_bn);
  }

  sprintf(tmp_bnstr, "%d", i-1);
  BN_dec2bn(&tmp_bn, tmp_bnstr);
  BN_div(avg_dlkg, reminder, avg_dlkg, tmp_bn, CTX);
  BN_div(avg_dlfc, reminder, avg_dlfc, tmp_bn, CTX);
  free(tmp_bnstr);

  //dump arrays into files
  for(i = 0; i <= chain_length; i++) {
    sprintf(tmp_str, "%d", i);
    fputs(tmp_str, fp_dlkg); fputs("\t", fp_dlkg);
    fputs(tmp_str, fp_dlfc); fputs("\t", fp_dlfc);
    fputs(tmp_str, fp_avg_dlkg); fputs("\t", fp_avg_dlkg);

    fputs(BN_bn2dec(avg_dlkg), fp_avg_dlkg); fputs("\n", fp_avg_dlkg);
    fputs(tmp_str, fp_avg_dlfc); fputs("\t", fp_avg_dlfc);
    fputs(BN_bn2dec(avg_dlfc), fp_avg_dlfc); fputs("\n", fp_avg_dlfc);
    sprintf(tmp_str, "%.f", time_dlkg[i]); fputs(tmp_str, fp_dlkg); fputs("\n", fp_dlkg);
    sprintf(tmp_str, "%.f", time_dlfc[i]); fputs(tmp_str, fp_dlfc); fputs("\n", fp_dlfc);
  }



  //fulsh buffers into files by closing file pointers
  fclose(fp_dlkg);
  fclose(fp_dlfc);
  fclose(fp_avg_dlkg);
  fclose(fp_avg_dlfc);
  //free resources
  free(dir); free(tmp_str);
  free(file_dlkg); free(file_dlfc);
  free(file_avg_dlkg); free(file_avg_dlfc);


  BN_free(bnRandom1);
  BN_free(bnRandom2);
  BN_free(bnChamDigest1);
  BN_free(bnChamDigest2);

  BN_CTX_free(bnCtx);
  BN_CTX_free(CTX);

  return 1;
}

int AF(int iSctyPrmtr, int chain_length){
  char *dir, *tmp_str, *tmp_bnstr, *file_afkg, *file_afhg, *file_affc, *file_avg_afkg, *file_avg_afhg, *file_avg_affc;
  FILE *fp_afkg, *fp_afhg, *fp_affc,
    *fp_avg_afkg, *fp_avg_afhg, *fp_avg_affc;
  double time_afkg[chain_length], time_afhg[chain_length], time_affc[chain_length];

  BIGNUM *tmp_bn = BN_new(), *reminder = BN_new();
  BN_CTX *CTX = BN_CTX_new();
  BIGNUM *avg_afkg = BN_new(), *avg_affc = BN_new();

  BIGNUM *bnRandom1 = BN_new();
  BIGNUM *bnRandom2 = BN_new();
  BIGNUM *bnChamDigest1 = BN_new();
  BIGNUM *bnChamDigest2 = BN_new();
  BN_CTX *bnCtx = BN_CTX_new();
  unsigned char* pchMsg1 = "ABCD";
  unsigned char* pchMsg2 = "PQRS";
  struct csKeys_AF csk;
  int i;

  dir = (char *)malloc(200); tmp_str = (char *)malloc(200);
  file_afkg = (char *)malloc(200);  file_afhg = (char *)malloc(200);  file_affc = (char *)malloc(200);
  file_avg_afkg = (char *)malloc(200);  file_avg_afhg = (char *)malloc(200);  file_avg_affc = (char *)malloc(200);
  dir = getcwd(dir, 200);

  for(i = 0; i <= chain_length; i++) {
    start_counter();
    if (CS_GenChamKeys_AF(iSctyPrmtr, &csk) == 0) {
      return 0;
    }
    if (CS_Rnd((BIGNUM*)(csk.CK.lambda), bnRandom1) == 0) {
      return 0;
    }
    if (CS_ChamHash_AF(iSctyPrmtr, pchMsg1, bnRandom1, csk.HK, bnChamDigest1) == 0) {
      return 0;
    }
    time_afkg[i] = get_counter();

    start_counter();
    if (CS_ClsnFind_AF(iSctyPrmtr, bnRandom1, pchMsg1, pchMsg2, csk.CK, bnRandom2) == 0) {
      return 0;
    }
    if (CS_ChamHash_AF(iSctyPrmtr, pchMsg2, bnRandom2, csk.HK, bnChamDigest2) == 0) {
      return 0;
    }
    if (BN_cmp(bnChamDigest1, bnChamDigest2) != 0) {
      return 0;
    }
    time_affc[i] = get_counter();
    }

    strcpy(file_afkg, dir);     strcpy(file_affc, dir);
    strcpy(file_avg_afkg, dir);   strcpy(file_avg_affc, dir);
    strcat(file_afkg, "/results/afkg_data.txt");
    strcat(file_afhg, "/results/afhg_data.txt");
    strcat(file_affc, "/results/affc_data.txt");
    strcat(file_avg_afkg, "/results/avg_afkg_data.txt");
    strcat(file_avg_afhg, "/results/avg_afhg_data.txt");
    strcat(file_avg_affc, "/results/avg_affc_data.txt");
    fp_afkg = fopen(file_afkg, "w+");
    fp_affc = fopen(file_affc, "w+");
    fp_avg_afkg = fopen(file_avg_afkg, "w+");
    fp_avg_affc = fopen(file_avg_affc, "w+");



    //compute average values of kg and fc
    BN_zero(avg_afkg); BN_zero(avg_affc);
    tmp_bnstr = (unsigned char *)malloc(2000);
    for(i = 0; i <= chain_length; i++) {
      sprintf(tmp_bnstr, "%.f", time_afkg[i]);
      BN_dec2bn(&tmp_bn, tmp_bnstr);
      BN_add(avg_afkg, avg_afkg, tmp_bn);

      sprintf(tmp_bnstr, "%.f", time_affc[i]);
      BN_dec2bn(&tmp_bn, tmp_bnstr);
      BN_add(avg_affc, avg_affc, tmp_bn);
    }
    sprintf(tmp_bnstr, "%d", i);
    BN_dec2bn(&tmp_bn, tmp_bnstr);
    BN_div(avg_afkg, reminder, avg_afkg, tmp_bn, CTX);
    BN_div(avg_affc, reminder, avg_affc, tmp_bn, CTX);
    free(tmp_bnstr);

    //dump arrays into files
    for(i = 0; i <= chain_length; i++) {
      sprintf(tmp_str, "%d", i);
      fputs(tmp_str, fp_afkg); fputs("\t", fp_afkg);
      fputs(tmp_str, fp_affc); fputs("\t", fp_affc);
      fputs(tmp_str, fp_avg_afkg); fputs("\t", fp_avg_afkg);
      fputs(BN_bn2dec(avg_afkg), fp_avg_afkg); fputs("\n", fp_avg_afkg);
      fputs(tmp_str, fp_avg_affc); fputs("\t", fp_avg_affc);
      fputs(BN_bn2dec(avg_affc), fp_avg_affc); fputs("\n", fp_avg_affc);
      sprintf(tmp_str, "%.f", time_afkg[i]); fputs(tmp_str, fp_afkg); fputs("\n", fp_afkg);
      sprintf(tmp_str, "%.f", time_affc[i]); fputs(tmp_str, fp_affc); fputs("\n", fp_affc);
    }

    //fulsh buffers into files by closing file pointers
    fclose(fp_afkg);
    fclose(fp_affc);
    fclose(fp_avg_afkg);
    fclose(fp_avg_affc);
    //free resources
    free(dir); free(tmp_str);
    free(file_afkg); free(file_affc);
    free(file_avg_afkg); free(file_avg_affc);

  BN_free(bnRandom1);
  BN_free(bnRandom2);
  BN_free(bnChamDigest1);
  BN_free(bnChamDigest2);

  BN_CTX_free(bnCtx);
  BN_CTX_free(CTX);

  return 1;
}
