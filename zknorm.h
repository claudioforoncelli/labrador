#ifndef ZKNORM_H
#define ZKNORM_H

/*
  Pi_zk-norm -- zero-knowledge approximate norm check (JL projection with a
  Gaussian mask and rejection sampling), following Faonio-Tong,
  ePrint 2026/1822, Sec. 7.3, Fig. 8.

  Reduction of knowledge  (ist, iwt) -> (ost, owt):

    Prover                                              Verifier
    y  <- D_sigma^256           (Gaussian mask)
    yhat = bindec(y),  r <- ternary (hiding randomness)
    c_y = Com(yhat || r)                 --- c_y --->
                                         <-- Pi ----    JL matrix, Bin1 entries
    z = Pi * s + y
    rejection sampling Rej(z, Pi*s, sigma, M)
      (on reject: restart with fresh y, r)
                                         --- z ----->   check ||z|| <= sqrt(512)*sigma

  Output statement:
    - witness vectors:  the input ones, plus one new vector (yhat || r)
    - Rq constraints:   the input ones + the commitment constraint Com(yhat||r) = c_y
    - Zq constraints:   the input ones + the projection constraints
                          ct( <sigma^-1(pi_k), s> + y_k - z_k ) = 0   (paper Eq. 5)

  Implementation notes (deviations that do not change the protocol):
    - y is stored in the witness through its binary decomposition yhat, so the
      new witness vector has small norm (as done in lnp.c).
    - The 256 projection constraints are not materialized one by one (each
      would carry a dense vector as long as the witness). Instead the verifier
      immediately sends LIFTS random Zq-combinations of them (public coin, no
      prover message) and only those combinations are output. A false row
      survives with probability 1/q per combination.
    - The projection of the inner-commitment digits t (z2/y2 in Fig. 8) is not
      implemented: the input statement of this layer carries no commitment.
*/

#include <stddef.h>
#include <stdint.h>
#include "polz.h"
#include "proofsystem.h"

typedef struct _zkn_params {
  size_t nn_in;          // total length of the input witness
  long double beta;      // l2 bound on the whole input witness
  long double sd;        // standard deviation of the mask y (= 1.55*2^logsd)
  unsigned int logsd;
  long double capm;      // rejection-sampling repetition rate M
  size_t ybits;          // bits used to decompose y (two's complement)
  size_t kappa;          // rank of the commitment c_y
  size_t rlen;           // ternary hiding randomness (polys)
  size_t wlen;           // new witness vector length = ybits + rlen
} zkn_params[1];

typedef struct _zkn_proof {
  polz *cy;              // commitment to (yhat || r), kappa polys
  int32_t z[256];        // masked projection
  size_t nrej;           // statistics: number of rejections (not sent)
} zkn_proof[1];

int  zkn_params_gen(zkn_params pp, const statement ist);
void zkn_params_print(const zkn_params pp);

void zkn_proof_init(zkn_proof pi, const zkn_params pp);
void zkn_proof_free(zkn_proof pi);

void zkn_prove(zkn_proof pi, statement ost, witness owt, const statement ist,
               const witness iwt, const zkn_params pp);
int  zkn_reduce(statement ost, const statement ist, const zkn_proof pi,
                const zkn_params pp);

#endif
