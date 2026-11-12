#include <math.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "zkagg.h"
#include "constraints.h"
#include "proofsystem.h"
#include "comkey.h"
#include "polx.h"
#include "polz.h"
#include "poly.h"
#include "malloc.h"
#include "randombytes.h"

#define ZKA_LAMBDA 128   // statistical security parameter for hiding

/*
  Parameters.
  - Hiding of c_g (paper Lemma 32): Com(ghat || r) is statistically close to
    uniform when the ternary randomness r has rlen > (kappa*log q + 2*lambda/N)
    / log2(3) polynomials.
  - Binding of c_g: MSIS of rank kappa for norm 2*||(ghat || r)||.
  Returns 1 if no secure parameters are found.
*/
int zka_params_gen(zka_params pp, const statement ist){
  size_t i, kappa;
  double norm;

  pp->nn_in = 0;
  for(i=0;i<ist->r;i++){
    pp->nn_in += ist->n[i];
  }
  pp->glen = LIFTS * LOGQ;

  for(kappa=1;kappa<=32;kappa++){
    pp->kappa = kappa;
    pp->rlen = (size_t) ceil((kappa*LOGQ + 2.0*ZKA_LAMBDA/N) / log2(3.0)) + 1;
    pp->wlen = pp->glen + pp->rlen;
    norm = sqrt((double) N * pp->wlen); // binary and ternary coefficients
    if(sis_secure(kappa, 2*norm)){
      return 0;
    }
  }
  return 1;
}

void zka_params_print(const zka_params pp){
  printf("zka params: kappa=%zu, glen=%zu, rlen=%zu, wlen=%zu, nn_in=%zu\n",
         pp->kappa, pp->glen, pp->rlen, pp->wlen, pp->nn_in);
}

void zka_proof_init(zka_proof pi, const zka_params pp){
  pi->m[0] = _aligned_alloc(64, (pp->kappa + LIFTS) * sizeof(polz));
  pi->m[1] = &pi->m[0][pp->kappa];
}

void zka_proof_free(zka_proof pi){
  free(pi->m[0]);
}

/*
  Sample the challenges psi (from the hash h) and aggregate the Zq constraints
  of ist into LIFTS constraints zqagg[k], each with a single linear part that
  covers the whole input witness. Same as ldr_aggregate_zq without the JL part.
*/
static void zka_aggregate_zq(
  sparsecnst zqagg[LIFTS],
  const statement ist,
  const zka_params pp,
  uint8_t h[16]
)
{
  size_t i, nchalz, nchalx;
  int64_t *chalz;
  polxvec chalx;

  nchalz = ist->zqcnst->sparse_nchal + ist->zqcnst->int_nchal;
  nchalx = ist->zqcnst->sigmam1_nchal;
  chalz = _aligned_alloc(64, (nchalz + 1) * sizeof(int64_t));
  if(nchalx > 0){
    polxvec_init(chalx, nchalx, 1);
  }

  for(i=0;i<LIFTS;i++){
    sample_chalz(chalz, nchalz, h);
    if(nchalx > 0){
      sample_chalx_uniform(chalx, h);
    }

    sparsecnst_init(zqagg[i], 1);
    quadfunc_init(zqagg[i]->quad, 0, (ist->r * ist->r + ist->r)/2);
    // 2 parts: [0] the input witness, [1] the digits ghat_i (added later)
    linfunc_init(zqagg[i]->lin, 1, 1, 2);
    zqagg[i]->lin->off[0] = 0;
    polxvec_init(zqagg[i]->lin->phi[0], pp->nn_in, 1);
    polxvec_setzero(zqagg[i]->lin->phi[0], 0, 1, pp->nn_in);

    zqcnstset_aggregate_add(zqagg[i], ist->zqcnst, chalz, chalx);

    sparsecnst_refresh(zqagg[i]);
    zqagg[i]->quad->coeffs = realloc(zqagg[i]->quad->coeffs,
                                     zqagg[i]->quad->len*sizeof(polx));
  }

  free(chalz);
  if(nchalx > 0){
    polxvec_free(chalx);
  }
}

/*
  Turn the aggregated constraints into full Rq constraints using the masked
  lifts b_k, and assemble the output statement. Shared by prover and verifier.
  Takes ownership of zqagg.
*/
static void zka_finish_statement(
  statement ost,
  const statement ist,
  const zka_proof pi,
  const zka_params pp,
  sparsecnst zqagg[LIFTS]
)
{
  size_t i, ns, nc;
  polxvec liftx, liftx_sv;

  // b_k is added to the right-hand side; the digits of g_k enter linearly
  // with gadget (1, 2, ..., 2^(LOGQ-2), -2^(LOGQ-1)) (two's complement bindec)
  polxvec_init(liftx, LIFTS, 1);
  polzvec_topolxvec(liftx, pi->m[1], 0, 1, LIFTS);
  for(i=0;i<LIFTS;i++){
    polxvec_init_subvec2(liftx_sv, liftx, i, 1, 1);
    polxvec_refresh(liftx_sv);
    polxvec_refresh(zqagg[i]->b);
    polxvec_add(zqagg[i]->b, zqagg[i]->b, liftx_sv);
    polxvec_refresh(zqagg[i]->b);

    zqagg[i]->lin->nparts = 2;
    zqagg[i]->lin->off[1] = pp->nn_in + i*LOGQ;
    polxvec_init(zqagg[i]->lin->phi[1], LOGQ, 1);
    polxvec_powers(zqagg[i]->lin->phi[1], 2, 1, -1);
  }
  polxvec_free(liftx);

  // witness vectors: input vectors + (ghat || r)
  statement_init(ost, ist->r + 1, ist->r + 1);
  for(i=0;i<ist->r;i++){
    ost->n[i] = ist->n[i];
    ost->normsq[i] = ist->normsq[i];
    ost->normsq_req[i] = ist->normsq_req[i];
    ost->normty[i] = ist->normty[i];
  }
  ost->n[ist->r] = pp->wlen;
  ost->normsq[ist->r] = (uint64_t) N * pp->wlen;
  ost->normty[ist->r] = L2APPROX;

  // Rq constraints: input ones + LIFTS new sparse + 1 commitment constraint
  ns = ist->rqcnst->nsparse;
  nc = ist->rqcnst->ncom;
  rqcnstset_free(ost->rqcnst);
  rqcnstset_init(ost->rqcnst, ns + LIFTS, nc + 1);
  for(i=0;i<ns;i++){
    sparsecnst_copy(ost->rqcnst->sparse[i], ist->rqcnst->sparse[i]);
  }
  for(i=0;i<LIFTS;i++){
    *ost->rqcnst->sparse[ns + i] = *zqagg[i];   // move
  }
  for(i=0;i<nc;i++){
    comcnst_copy(ost->rqcnst->com[i], ist->rqcnst->com[i]);
  }
  ps_addcheck_commit_in_clear(ost->rqcnst->com[nc], pi->m[0], pp->kappa,
                              pp->nn_in, pp->wlen);
  ost->rqcnst->sparse_nchal = ist->rqcnst->sparse_nchal + LIFTS;
  ost->rqcnst->com_nchal = ist->rqcnst->com_nchal + pp->kappa;

  // Zq constraints: none left (statement_init leaves the set empty)
}

void zka_prove(
  zka_proof pi,
  statement ost,
  witness owt,
  const statement ist,
  const witness iwt,
  const zka_params pp
)
{
  size_t i, j, off;
  uint8_t seed[16], h[16];
  polz g[LIFTS];
  poly *w;
  polxvec sxl, *sxq, wx, cgx, liftx, gx;
  sparsecnst zqagg[LIFTS];

  randombytes(seed, 16);
  comkey_init(pp->wlen);

  // Output witness: input vectors followed by w = (ghat || r)

  witness_init(owt, ist->r + 1, ist->r + 1);
  owt->s[0] = _aligned_alloc(64, (pp->nn_in + pp->wlen) * sizeof(poly));
  for(i=0;i<ist->r;i++){
    owt->n[i] = iwt->n[i];
    if(i > 0) owt->s[i] = &owt->s[i-1][owt->n[i-1]];
  }
  owt->n[ist->r] = pp->wlen;
  owt->s[ist->r] = &owt->s[0][pp->nn_in];
  polyvec_copy(owt->s[0], iwt->s[0], 1, 1, pp->nn_in);
  w = owt->s[ist->r];

  // Masks g_k: ct = 0, other coefficients uniform mod q

  polzvec_uniform(g, LIFTS, seed, 0);
  for(i=0;i<LIFTS;i++){
    for(j=0;j<L;j++){
      g[i]->limbs[j]->c[0] = 0;
    }
    polz_reduce(g[i]);
    polz_center(g[i]);
    polzvec_bindec(&w[i*LOGQ], &g[i], 1, 1, LOGQ);
  }
  assert(polyvec_isbinary(w, 1, pp->glen));

  // Hiding randomness r (ternary)

  polyvec_ternary(&w[pp->glen], 1, pp->rlen, seed, 1);

  // Commitment c_g = Com(ghat || r)

  polxvec_init(wx, pp->wlen, 1);
  polxvec_frompolyvec(wx, w, 1, pp->wlen, 1);
  polxvec_init(cgx, pp->kappa, 1);
  commit(cgx, wx);
  polzvec_frompolxvec(pi->m[0], cgx, 0, 1, pp->kappa);

  memcpy(h, ist->h, 16);
  update_hash_polz(h, pi->m[0], pp->kappa);

  // Challenges psi and aggregation of the Zq constraints

  zka_aggregate_zq(zqagg, ist, pp, h);

  // Masked lifts b_k = sum_j psi_kj f'_j(s) + g_k   (ct(b_k) = 0)

  polxvec_init(sxl, pp->nn_in, 1);
  polxvec_frompolyvec(sxl, iwt->s[0], 1, pp->nn_in, 1);
  sxq = _malloc(ist->r * sizeof(polxvec));
  off = 0;
  for(i=0;i<ist->r;i++){
    polxvec_setwidths1(sxl, off, 1, ist->n[i], ist->normsq[i]/(ist->n[i]*N));
    polxvec_init_subvec2(sxq[i], sxl, off, 1, ist->n[i]);
    off += ist->n[i];
  }

  polxvec_init(liftx, 1, 1);
  polxvec_init(gx, 1, 1);
  for(i=0;i<LIFTS;i++){
    sparsecnst_eval(liftx, zqagg[i], sxq, sxl);
    assert(polxvec_iszero_constcoeff(liftx, 0)); // input Zq constraints hold
    polxvec_refresh(liftx);
    polzvec_topolxvec(gx, &g[i], 0, 1, 1);
    polxvec_refresh(gx);
    polxvec_add(liftx, liftx, gx);
    polxvec_refresh(liftx);
    polzvec_frompolxvec(&pi->m[1][i], liftx, 0, 1, 1);
  }
  update_hash_polz(h, pi->m[1], LIFTS);

  // Output statement

  zka_finish_statement(ost, ist, pi, pp, zqagg);
  memcpy(ost->h, h, 16);

  polxvec_free(sxl);
  polxvec_free(wx);
  polxvec_free(cgx);
  polxvec_free(liftx);
  polxvec_free(gx);
  free(sxq);
}

/*
  Returns 0 on success, 1 if the constant coefficient of a lift is not zero.
*/
int zka_reduce(
  statement ost,
  const statement ist,
  const zka_proof pi,
  const zka_params pp
)
{
  size_t i;
  int check;
  uint8_t h[16];
  polxvec liftx;
  sparsecnst zqagg[LIFTS];

  comkey_init(pp->wlen);

  memcpy(h, ist->h, 16);
  update_hash_polz(h, pi->m[0], pp->kappa);

  zka_aggregate_zq(zqagg, ist, pp, h);

  // Check ct(b_k) = 0

  polxvec_init(liftx, LIFTS, 1);
  polzvec_topolxvec(liftx, pi->m[1], 0, 1, LIFTS);
  check = 1;
  for(i=0;i<LIFTS;i++){
    check &= polxvec_iszero_constcoeff(liftx, i);
  }
  polxvec_free(liftx);
  if(!check){
    for(i=0;i<LIFTS;i++){
      sparsecnst_free(zqagg[i]);
    }
    return 1;
  }

  update_hash_polz(h, pi->m[1], LIFTS);

  zka_finish_statement(ost, ist, pi, pp, zqagg);
  memcpy(ost->h, h, 16);
  return 0;
}
