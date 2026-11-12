#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "zknorm.h"
#include "zkagg.h"
#include "labrador.h"
#include "labrador_core.h"
#include "proofsystem.h"
#include "polx.h"
#include "test_proofsystem_setup.h"
#include "randombytes.h"
#include "comkey.h"
#include "malloc.h"

static int nfail = 0;
static size_t total_rej = 0, total_runs = 0;

#define FAIL(...) do { fprintf(stderr, "FAIL: " __VA_ARGS__); nfail++; } while(0)

/*
  1. Completeness of zk-norm: prove -> verify(ostp); reduce -> verify(ostv);
     same transcript hash on both sides.
  2. Soundness sanity: an oversized z is rejected; a modified z coordinate
     makes the witness fail the projection constraints.
  3. Composition (one zk "norm + aggregation" block followed by LaBRADOR):
       zk-norm -> zk-agg' -> LaBRADOR      (all outputs verify)
*/
static void test_zkn(const uint8_t seed[16], size_t r, size_t len, size_t ncnst,
                     int compose){
  size_t nn, iwtbits, pibits, owtbits, nonce = 0;
  polxvec sxl, *sxq;
  statement ist, ostp, ostv, st2p, st2v, st3p, st3v;
  witness iwt, owt, owt2, owt3;
  zkn_params pp;
  zkn_proof pi;
  zka_params app;
  zka_proof api;
  lab_params lpp;
  lab_proof lpi;
  int32_t zsave;

  witness_init(iwt, r, r);
  ps_witness_set(iwt, sxl, &sxq, &nn, &iwtbits, len, seed, &nonce);
  comkey_init(nn);
  statement_init(ist, r, r);
  ps_statement_set(ist, iwt, sxl, sxq, nn, ncnst, seed, &nonce);
  if(!verify(ist, iwt)){ FAIL("input statement does not verify\n"); goto out0; }
  if(zkn_params_gen(pp, ist)){ FAIL("no zkn parameters\n"); goto out0; }

  // 1. completeness
  zkn_proof_init(pi, pp);
  zkn_prove(pi, ostp, owt, ist, iwt, pp);
  total_rej += pi->nrej; total_runs++;
  fprintf(stderr, "  zkn_prove done, %zu rejections\n", pi->nrej);
  if(!verify(ostp, owt)) FAIL("r=%zu len=%zu: prover output does not verify\n", r, len);
  if(zkn_reduce(ostv, ist, pi, pp)){ FAIL("honest proof rejected\n"); goto out1; }
  if(!verify(ostv, owt)) FAIL("r=%zu len=%zu: verifier output does not verify\n", r, len);
  if(memcmp(ostp->h, ostv->h, 16)) FAIL("prover/verifier hash mismatch\n");

  // 3. composition: zk-norm -> zk-agg' -> LaBRADOR
  if(compose){
    if(zka_params_gen(app, ostv)) FAIL("no zka parameters\n");
    else {
      zka_proof_init(api, app);
      zka_prove(api, st2p, owt2, ostp, owt, app);
      if(zka_reduce(st2v, ostv, api, app)) FAIL("zk-agg' rejects\n");
      else {
        if(!verify(st2v, owt2)) FAIL("zk-agg' output does not verify\n");
        if(lab_params_gen(lpp, &pibits, &owtbits, st2v, 0, 0, 0, 1, 1, JL_L2_SLACK))
          FAIL("no LaBRADOR params\n");
        else {
          ldr_prove(lpi, st3p, owt3, st2p, owt2, lpp);
          if(ldr_reduce(st3v, st2v, lpi, lpp)) FAIL("LaBRADOR rejects\n");
          else {
            if(!verify(st3v, owt3)) FAIL("LaBRADOR output does not verify\n");
            statement_free(st3v);
          }
          statement_free(st3p); witness_free(owt3);
          lab_proof_free(lpi); lab_params_free(lpp);
        }
        statement_free(st2v);
      }
      statement_free(st2p); witness_free(owt2); zka_proof_free(api);
    }
  }
  statement_free(ostv);

  // 2a. oversized z must be rejected
  zsave = pi->z[3];
  pi->z[3] = (int32_t)(30 * pp->sd);
  if(!zkn_reduce(ostv, ist, pi, pp)){ FAIL("oversized z accepted\n"); statement_free(ostv); }
  // 2b. slightly modified z: the projection constraints no longer hold
  pi->z[3] = zsave + 1;
  if(zkn_reduce(ostv, ist, pi, pp)) FAIL("unexpected reject\n");
  else {
    fprintf(stderr, "(expected error below) ");
    if(verify(ostv, owt)) FAIL("modified z still verifies\n");
    statement_free(ostv);
  }
  pi->z[3] = zsave;

out1:
  statement_free(ostp);
  witness_free(owt);
  zkn_proof_free(pi);
out0:
  free(sxq);
  polxvec_free(sxl);
  statement_free(ist);
  witness_free(iwt);
  comkey_free();
}

int main(int argc, char **argv){
  size_t first = argc > 1 ? (size_t) atoi(argv[1]) : 0;
  size_t i, j;
  size_t niter[5]   = {10,   3,    2,    1,     1};
  size_t r[5]       = {1,    5,    2,    3,     1};
  size_t len[5]     = {1000, 1000, 5000, 8000,  1000};
  size_t ncnst[5]   = {5,    5,    3,    2,     0};
  int compose[5]    = {0,    1,    1,    1,     1};
  uint8_t seed[16];
  zkn_params pp;
  statement st;

  for(i=first;i<5;i++){
    for(j=0;j<niter[i];j++){
      randombytes(seed, 16);
      fprintf(stderr, "[case r=%zu len=%zu compose=%d]\n", r[i], len[i], compose[i]);
      test_zkn(seed, r[i], len[i], ncnst[i], compose[i]);
    }
  }

  statement_init(st, 1, 1);
  st->n[0] = 1000; st->normsq[0] = 1000 * N;
  zkn_params_gen(pp, st);
  zkn_params_print(pp);
  statement_free(st);
  printf("average rejections per proof: %.2f (expected about M-1 = %.2Lf)\n",
         (double) total_rej / total_runs, pp->capm - 1);

  printf(nfail ? "test_zknorm: %d FAILURES\n" : "test_zknorm: all tests passed\n", nfail);
  return nfail != 0;
}
