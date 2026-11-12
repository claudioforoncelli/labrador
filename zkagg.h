#ifndef ZKAGG_H
#define ZKAGG_H

/*
  Pi_zk-agg' -- zero-knowledge aggregation of the constant-term (Zq)
  constraints, following Faonio-Tong, ePrint 2026/1822, Sec. 7.4 and App. B.2.

  Reduction of knowledge  (ist, iwt) -> (ost, owt):

    Prover                                              Verifier
    g_k <- Rq, ct(g_k) = 0, other coeffs uniform  (k < LIFTS = lambda')
    ghat = bindec(g)  (binary digits),  r <- ternary (hiding randomness)
    c_g  = Com(ghat || r)                 --- c_g --->
                                          <-- psi ---   psi_k in Zq^{K'}
    b_k  = g_k + sum_j psi_kj q'_j(s)     --- b_k --->  check ct(b_k) = 0
                                                        (ct of b'_j folded in)

  Output statement:
    - witness vectors:  the input ones, plus one new vector (ghat || r)
    - Rq constraints:   the input ones,
                        + LIFTS constraints  sum_j psi_kj f'_j(s) + G*ghat_k = b_k
                        + the commitment constraint  Com(ghat || r) = c_g
    - Zq constraints:   none (all aggregated)

  The proof is (c_g, b_1..b_LIFTS); b_k is sent in the clear and its higher
  coefficients are uniformly random because of g_k (partial zero-knowledge).
*/

#include <stddef.h>
#include "polz.h"
#include "proofsystem.h"

typedef struct _zka_params {
  size_t kappa;    // rank of the commitment c_g
  size_t glen;     // number of binary polynomials in ghat (= LIFTS * LOGQ)
  size_t rlen;     // number of ternary polynomials of hiding randomness r
  size_t wlen;     // length of the new witness vector (= glen + rlen)
  size_t nn_in;    // total length of the input witness (offset of new vector)
} zka_params[1];

typedef struct _zka_proof {
  polz *m[2];      // m[0]: c_g (kappa polys), m[1]: masked lifts b_k (LIFTS)
} zka_proof[1];

int  zka_params_gen(zka_params pp, const statement ist);
void zka_params_print(const zka_params pp);

void zka_proof_init(zka_proof pi, const zka_params pp);
void zka_proof_free(zka_proof pi);

void zka_prove(zka_proof pi, statement ost, witness owt, const statement ist,
               const witness iwt, const zka_params pp);
int  zka_reduce(statement ost, const statement ist, const zka_proof pi,
                const zka_params pp);

#endif
