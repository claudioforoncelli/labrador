#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "zknorm.h"
#include "constraints.h"
#include "proofsystem.h"
#include "comkey.h"
#include "aesctr.h"
#include "fips202.h"
#include "gaussian.h"
#include "rejection.h"
#include "jlproj.h"
#include "polx.h"
#include "polz.h"
#include "poly.h"
#include "malloc.h"
#include "randombytes.h"

#define ZKN_LAMBDA   128  // statistical security parameter for hiding
#define ZKN_GAMMA    16   // sigma = gamma * (bound on ||Pi*s||), as in lnp.c
#define ZKN_GTAIL    14   // Gaussian tail bound (in standard deviations)
#define ZKN_YEXTRA   6    // extra bits for yhat beyond logsd (lnp.c YHAT_EXTRA_BITS)

static int64_t modq_centered(__int128 a){
  const int64_t q = ((int64_t)1 << LOGQ) - QOFF;
  a %= q;
  if(a > q/2) a -= q;
  if(a < -(q/2)) a += q;
  return (int64_t) a;
}

/*
  Parameters.
  - ||Pi*s|| <= sqrt(JL_L2_MULT) * beta  w.h.p. (beta^2 = sum of input normsq)
  - sigma = ZKN_GAMMA * that bound, rounded to 1.55*2^logsd (sampler format),
    M = exp(GTAIL/gamma + 1/(2 gamma^2))  (same formula as lnp.c)
  - hiding randomness and commitment rank as in zkagg.c (paper Lemma 32).
  Returns 1 if no secure parameters are found.
*/
int zkn_params_gen(zkn_params pp, const statement ist){
  size_t i, kappa;
  long double normsq, t, gamma;
  double norm;

  pp->nn_in = 0;
  normsq = 0;
  for(i=0;i<ist->r;i++){
    pp->nn_in += ist->n[i];
    normsq += ist->normsq[i];
  }
  pp->beta = sqrtl(normsq);

  t = sqrtl(JL_L2_MULT) * pp->beta;
  pp->logsd = (unsigned int) roundl(log2l(ZKN_GAMMA * t / 1.55L));
  pp->sd = ldexpl(1.55L, (int) pp->logsd);
  gamma = pp->sd / t;
  pp->capm = expl(ZKN_GTAIL / gamma + 1 / (2 * gamma * gamma));
  pp->ybits = pp->logsd + ZKN_YEXTRA;

  // z must fit in 32 bits, and the projection equations must not wrap mod q
  if(ZKN_GTAIL * pp->sd >= (1UL << 30)) return 1;
  if(sqrtl(512) * pp->sd * 125 >= (long double)(((uint64_t)1 << LOGQ) - QOFF))
    return 1;

  for(kappa=1;kappa<=32;kappa++){
    pp->kappa = kappa;
    pp->rlen = (size_t) ceil((kappa*LOGQ + 2.0*ZKN_LAMBDA/N) / log2(3.0)) + 1;
    pp->wlen = pp->ybits + pp->rlen;
    norm = sqrt((double) N * pp->wlen);
    if(sis_secure(kappa, 2*norm)){
      return 0;
    }
  }
  return 1;
}

void zkn_params_print(const zkn_params pp){
  printf("zkn params: nn_in=%zu, beta=%.1Lf, sd=1.55*2^%u=%.1Lf, M=%.3Lf, "
         "ybits=%zu, kappa=%zu, rlen=%zu, wlen=%zu\n", pp->nn_in, pp->beta,
         pp->logsd, pp->sd, pp->capm, pp->ybits, pp->kappa, pp->rlen, pp->wlen);
}

void zkn_proof_init(zkn_proof pi, const zkn_params pp){
  pi->cy = _aligned_alloc(64, pp->kappa * sizeof(polz));
  pi->nrej = 0;
}

void zkn_proof_free(zkn_proof pi){
  free(pi->cy);
}

static void hash_z(uint8_t h[16], const int32_t z[256]){
  uint8_t buf[16 + 1024];
  memcpy(buf, h, 16);
  memcpy(&buf[16], z, 1024);
  shake128(h, 16, buf, sizeof(buf));
}

/*
  Build the LIFTS random combinations of the 256 projection constraints
    ct( sum_k c_k * ( <sigma^-1(pi_k), s> + y_k - z_k ) ) = 0
  and append them to zq->sparse[off ..]. Shared by prover and verifier.
  - <phi, s> with phi = jl_aggregate_mat(c): ct = sum_k c_k (Pi s)_k
  - y = sum_b w_b yhat_b, w = (1, 2, .., 2^(B-2), -2^(B-1)), and for
    a = c_0 - sum_{k>0} c_k X^(N-k):  ct(a * y) = sum_k c_k y_k
  - right-hand side: sum_k c_k z_k mod q
*/
static void zkn_projection_cnsts(
  zqcnstset zq,
  size_t off,
  const zkn_params pp,
  const uint8_t *jlmat1,
  const uint8_t *jlmat2,
  const int32_t z[256],
  uint8_t h[16]
)
{
  size_t l, b, k;
  int64_t a[N], wa[N];
  __int128 w;
  sparsecnst *c;
  polxvec sv;
  __attribute__((aligned(64))) int64_t chalz[256];
  __attribute__((aligned(64))) uint8_t hashbuf[64 + QBYTES*256 + 24];

  for(l=0;l<LIFTS;l++){
    shake128(hashbuf, sizeof(hashbuf), h, 16);
    memcpy(h, hashbuf, 16);
    jlproj_expand_challenge(chalz, &hashbuf[64]);

    c = &zq->sparse[off + l];
    sparsecnst_init(*c, 1);
    linfunc_init((*c)->lin, 1, 2, 2);

    // part 0: the projected input witness
    (*c)->lin->off[0] = 0;
    polxvec_init((*c)->lin->phi[0], pp->nn_in, 1);
    jl_aggregate_mat((*c)->lin->phi[0], jlmat1, jlmat2, chalz);

    // part 1: the mask y through its binary digits yhat (N = 256 coefficients)
    a[0] = chalz[0];
    for(k=1;k<N;k++){
      a[N-k] = modq_centered(-(__int128)chalz[k]);
    }
    (*c)->lin->off[1] = pp->nn_in;
    polxvec_init((*c)->lin->phi[1], pp->ybits, 1);
    for(b=0;b<pp->ybits;b++){
      w = (__int128)1 << b;
      if(b == pp->ybits - 1) w = -w;
      for(k=0;k<N;k++){
        wa[k] = modq_centered(w * a[k]);
      }
      polxvec_init_subvec2(sv, (*c)->lin->phi[1], b, 1, 1);
      polxvec_fromint64vec2(sv, wa, 1, 1, WIDTHMOD(LOGQ));
    }

    // right-hand side
    polxvec_monomial((*c)->b, 0, 0, jlproj_collapsproj(z, chalz));

    sparsecnst_refresh(*c);
  }
}

/*
  Assemble the output statement (shared by prover and verifier).
*/
static void zkn_build_statement(
  statement ost,
  const statement ist,
  const zkn_proof pi,
  const zkn_params pp,
  const uint8_t *jlmat1,
  const uint8_t *jlmat2,
  uint8_t h[16]
)
{
  size_t i, ns, nsig, nint, nc;

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

  // Rq constraints: copy + Com(yhat || r) = c_y
  nc = ist->rqcnst->ncom;
  rqcnstset_free(ost->rqcnst);
  rqcnstset_init(ost->rqcnst, ist->rqcnst->nsparse, nc + 1);
  for(i=0;i<ist->rqcnst->nsparse;i++){
    sparsecnst_copy(ost->rqcnst->sparse[i], ist->rqcnst->sparse[i]);
  }
  for(i=0;i<nc;i++){
    comcnst_copy(ost->rqcnst->com[i], ist->rqcnst->com[i]);
  }
  ps_addcheck_commit_in_clear(ost->rqcnst->com[nc], pi->cy, pp->kappa,
                              pp->nn_in, pp->wlen);
  ost->rqcnst->sparse_nchal = ist->rqcnst->sparse_nchal;
  ost->rqcnst->com_nchal = ist->rqcnst->com_nchal + pp->kappa;

  // Zq constraints: copy + LIFTS projection combinations
  ns = ist->zqcnst->nsparse;
  nsig = ist->zqcnst->nsigmam1;
  nint = ist->zqcnst->nint;
  zqcnstset_free(ost->zqcnst);
  zqcnstset_init(ost->zqcnst, ns + LIFTS, ns + LIFTS, nsig, nsig, nint);
  for(i=0;i<ns;i++){
    sparsecnst_copy(ost->zqcnst->sparse[i], ist->zqcnst->sparse[i]);
  }
  for(i=0;i<nsig;i++){
    sigmam1cnst_copy(ost->zqcnst->sigmam1[i], ist->zqcnst->sigmam1[i]);
  }
  for(i=0;i<nint;i++){
    intcnst_copy(ost->zqcnst->intc[i], ist->zqcnst->intc[i]);
  }
  ost->zqcnst->sparse_nchal = ist->zqcnst->sparse_nchal + LIFTS;
  ost->zqcnst->sigmam1_nchal = ist->zqcnst->sigmam1_nchal;
  ost->zqcnst->int_nchal = ist->zqcnst->int_nchal;

  zkn_projection_cnsts(ost->zqcnst, ns, pp, jlmat1, jlmat2, pi->z, h);
  memcpy(ost->h, h, 16);
}

void zkn_prove(
  zkn_proof pi,
  statement ost,
  witness owt,
  const statement ist,
  const witness iwt,
  const zkn_params pp
)
{
  size_t i, k;
  int64_t zv, vv, y64[N];
  int32_t y[256], v[256], ymax;
  uint8_t seed[16], h[16], *jlmat1, *jlmat2;
  aes128ctr_ctx gstate, rstate;
  polz yz;
  poly *w;
  polxvec wx, cyx;

  randombytes(seed, 16);
  aes128ctr_init(&gstate, seed, 0);
  aes128ctr_init(&rstate, seed, 1);
  comkey_init(pp->wlen);

  // Output witness: input vectors followed by w = (yhat || r)

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

  polxvec_init(wx, pp->wlen, 1);
  polxvec_init(cyx, pp->kappa, 1);
  pi->nrej = 0;

  for(;;){
    // Gaussian mask y (resample in the negligible case it exceeds the tail)
    do {
      gaussian_i32(y, 256, &gstate, pp->logsd);
      ymax = 0;
      for(k=0;k<256;k++) ymax = (abs(y[k]) > ymax) ? abs(y[k]) : ymax;
    } while(ymax >= ((int32_t)1 << (pp->ybits - 1)));

    for(k=0;k<N;k++) y64[k] = y[k];
    polzvec_fromint64vec(&yz, 1, 1, y64);
    polzvec_bindec(w, &yz, 1, 1, pp->ybits);
    polyvec_ternary(&w[pp->ybits], 1, pp->rlen, seed, 2 + pi->nrej);

    // c_y = Com(yhat || r)
    polxvec_frompolyvec(wx, w, 1, pp->wlen, 1);
    commit(cyx, wx);
    polzvec_frompolxvec(pi->cy, cyx, 0, 1, pp->kappa);

    memcpy(h, ist->h, 16);
    update_hash_polz(h, pi->cy, pp->kappa);

    // JL challenge and masked projection z = Pi*s + y
    jl_sample_mat(&jlmat1, &jlmat2, h, pp->nn_in);
    jl_project(v, iwt->s[0], pp->nn_in, jlmat1, jlmat2);

    zv = vv = 0;
    for(k=0;k<256;k++){
      pi->z[k] = v[k] + y[k];
      zv += (int64_t) pi->z[k] * v[k];
      vv += (int64_t) v[k] * v[k];
    }

    // rejection sampling: accepted z is distributed as D_sigma, independent of s
    if(!is_rejected_std0(&rstate, zv, vv, pp->sd * pp->sd, pp->capm) &&
       jlproj_normsq(pi->z) <= 512 * pp->sd * pp->sd){
      break;
    }
    pi->nrej++;
    free(jlmat1);
  }

  hash_z(h, pi->z);
  zkn_build_statement(ost, ist, pi, pp, jlmat1, jlmat2, h);

  free(jlmat1);
  polxvec_free(wx);
  polxvec_free(cyx);
}

/*
  Returns 0 on success, 1 if ||z|| is too large.
*/
int zkn_reduce(
  statement ost,
  const statement ist,
  const zkn_proof pi,
  const zkn_params pp
)
{
  uint8_t h[16], *jlmat1, *jlmat2;

  if(jlproj_normsq(pi->z) > 512 * pp->sd * pp->sd){
    return 1;
  }

  comkey_init(pp->wlen);

  memcpy(h, ist->h, 16);
  update_hash_polz(h, pi->cy, pp->kappa);
  jl_sample_mat(&jlmat1, &jlmat2, h, pp->nn_in);
  hash_z(h, pi->z);

  zkn_build_statement(ost, ist, pi, pp, jlmat1, jlmat2, h);

  free(jlmat1);
  return 0;
}
