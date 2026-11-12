#include <stdio.h>
#include <string.h>
#include "zkagg.h"
#include "labrador.h"
#include "labrador_core.h"
#include "proofsystem.h"
#include "polx.h"
#include "polz.h"
#include "test_proofsystem_setup.h"
#include "randombytes.h"
#include "comkey.h"
#include "malloc.h"

static int nfail = 0;

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); nfail++; } while(0)

/*
  1. Completeness: zka_prove -> verify(ostp, owt); zka_reduce -> verify(ostv, owt)
     and prover/verifier derive the same transcript hash.
  2. Soundness sanity: a lift with non-zero constant coefficient is rejected,
     and a modified higher coefficient makes the witness fail the statement.
  3. Composition: the output of zk-agg' is accepted by plain LaBRADOR.
*/
static void test_zka(const uint8_t seed[16], size_t r, size_t len, size_t ncnst){
  size_t nn, iwtbits, pibits, owtbits, nonce = 0;
  polxvec sxl, *sxq;
  statement ist, ostp, ostv, ost2p, ost2v;
  witness iwt, owt, owt2;
  zka_params pp;
  zka_proof pi;
  lab_params lpp;
  lab_proof lpi;
  zz c;

  witness_init(iwt, r, r);
  ps_witness_set(iwt, sxl, &sxq, &nn, &iwtbits, len, seed, &nonce);
  comkey_init(nn);
  statement_init(ist, r, r);
  ps_statement_set(ist, iwt, sxl, sxq, nn, ncnst, seed, &nonce);
  if(!verify(ist, iwt)){
    FAIL("input statement does not verify\n");
    goto out0;
  }
  if(zka_params_gen(pp, ist)){
    FAIL("no parameters\n");
    goto out0;
  }

  // 1. completeness
  zka_proof_init(pi, pp);
  zka_prove(pi, ostp, owt, ist, iwt, pp);
  if(!verify(ostp, owt)) FAIL("r=%zu len=%zu: prover output does not verify\n", r, len);
  if(ostp->zqcnst->nsparse + ostp->zqcnst->nsigmam1 != 0) FAIL("Zq constraints left\n");

  if(zka_reduce(ostv, ist, pi, pp)){
    FAIL("r=%zu len=%zu: honest proof rejected\n", r, len);
    goto out1;
  }
  if(!verify(ostv, owt)) FAIL("r=%zu len=%zu: verifier output does not verify\n", r, len);
  if(memcmp(ostp->h, ostv->h, 16)) FAIL("prover/verifier hash mismatch\n");

  // 3. composition with plain LaBRADOR
  if(lab_params_gen(lpp, &pibits, &owtbits, ostv, 0, 0, 0, 1, 1, JL_L2_SLACK)){
    FAIL("no LaBRADOR params for zk-agg' output\n");
  }
  else{
    ldr_prove(lpi, ost2p, owt2, ostp, owt, lpp);
    if(!verify(ost2p, owt2)) FAIL("LaBRADOR prover output does not verify\n");
    if(ldr_reduce(ost2v, ostv, lpi, lpp)) FAIL("LaBRADOR rejects\n");
    else {
      if(!verify(ost2v, owt2)) FAIL("LaBRADOR verifier output does not verify\n");
      statement_free(ost2v);
    }
    statement_free(ost2p);
    witness_free(owt2);
    lab_proof_free(lpi);
    lab_params_free(lpp);
  }
  statement_free(ostv);

  // 2a. lift with non-zero constant coefficient must be rejected
  polz_getcoeff(c, pi->m[1][0], 0);
  polz_setcoeff_fromint64(pi->m[1][0], 1, 0);
  if(!zka_reduce(ostv, ist, pi, pp)){
    FAIL("tampered ct(b_0) accepted\n");
    statement_free(ostv);
  }
  polz_setcoeff(pi->m[1][0], c, 0);

  // 2b. tampered higher coefficient: the witness no longer satisfies it
  polz_setcoeff_fromint64(pi->m[1][0], 12345, 7);
  if(zka_reduce(ostv, ist, pi, pp)) FAIL("unexpected reject\n");
  else {
    fprintf(stderr, "(expected error below) ");
    if(verify(ostv, owt)) FAIL("tampered b_0 still verifies\n");
    statement_free(ostv);
  }

out1:
  statement_free(ostp);
  witness_free(owt);
  zka_proof_free(pi);
out0:
  free(sxq);
  polxvec_free(sxl);
  statement_free(ist);
  witness_free(iwt);
  comkey_free();
}

int main(void){
  size_t i, j;
  size_t niter[4] = {3,    3,    2,    1};
  size_t r[4]     = {1,    5,    2,    3};
  size_t len[4]   = {1000, 1000, 5000, 20000};
  size_t ncnst[4] = {5,    5,    3,    2};
  uint8_t seed[16];
  zka_params pp;
  statement st;

  for(i=0;i<4;i++){
    for(j=0;j<niter[i];j++){
      randombytes(seed, 16);
      test_zka(seed, r[i], len[i], ncnst[i]);
    }
  }

  statement_init(st, 1, 1);
  st->n[0] = 1000;
  zka_params_gen(pp, st);
  zka_params_print(pp);
  statement_free(st);

  printf(nfail ? "test_zkagg: %d FAILURES\n" : "test_zkagg: all tests passed\n", nfail);
  return nfail != 0;
}
