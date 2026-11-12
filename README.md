# LaBRADOR with zero-knowledge

This is a university project. It adds **zero-knowledge** to LaBRADOR, a lattice-based proof system, following the paper:

> A. Faonio and L. Tong, *Non-Malleable Reductions of Knowledge*, [ePrint 2026/1822](https://eprint.iacr.org/2026/1822), Section 7.

This repository is a fork of [lazer-crypto/labrador](https://github.com/lazer-crypto/labrador). The original code and README are there.

> [!WARNING]
> Research code. Not reviewed for security. Do not use in production.

## The idea in short

LaBRADOR lets a prover show "I know secret small numbers that solve these equations" with a very short proof.

**Problem:** the proof leaks a little information about the secret.

**Fix from the paper:** run a few extra steps *before* LaBRADOR that hide the secret behind random noise. Whatever LaBRADOR leaks afterwards is then useless.

The paper builds these extra steps from small pieces. This repository implements the first two pieces:

| Piece | What it does | Code |
|---|---|---|
| **zk-norm** | Proves the secret is small, without revealing it | `zknorm.c`, `zknorm.h` |
| **zk-agg′** | Merges some of the equations, without revealing anything | `zkagg.c`, `zkagg.h` |

Two more pieces (Π₁ and Π₂ in the paper) are still to do.

## How the two pieces work

**zk-norm**
- To prove the secret is small, LaBRADOR sends a random "summary" of it (a projection). This summary leaks information.
- Here, random noise is added to the summary before sending it.
- Sometimes the prover throws the result away and tries again with new noise (*rejection sampling*). This makes sure the result reveals nothing about the secret.

**zk-agg′**
- When LaBRADOR merges some equations, it sends a few values that leak information.
- Here, a random value is added to each of them before sending.
- The verifier can still do its check, because the random value is built not to disturb it.

Both pieces work like LaBRADOR's own `ldr_prove` / `ldr_reduce`. They take a statement and a witness, and output a new statement and witness that can go into the next piece or into LaBRADOR.

## What is simplified compared to the paper

- The random noise is stored as bits, but nothing checks yet that they really are bits.
- The commitment used to hide the noise is simpler than the paper's.
- zk-norm outputs 4 combined equations instead of 256 separate ones, because 256 would be too slow and use too much memory.
- One part of the paper's zk-norm (projecting `t`) is skipped.
- Some parameters are copied from existing code, not computed from the paper.

## What was added

Everything is in this folder. Six new files were added and the `Makefile` was extended. No existing LaBRADOR file was edited: the new code only *uses* existing functions (the Gaussian sampler, rejection sampling, commitments, the projection, and `verify()`).

Each module has a `.h` file (the list of functions) and a `.c` file (the code).

### `zkagg.h` / `zkagg.c`: zk-agg′

| Function | What it does |
|---|---|
| `zka_params_gen` | Chooses the sizes the step needs, e.g. how much random padding the commitment needs to hide the masks |
| `zka_prove` | **Prover:** creates the random masks, commits to them, merges the equations, adds a mask to each result and sends it, and builds the new statement and witness |
| `zka_reduce` | **Verifier:** checks the masked values, then builds the same new statement from the proof alone |
| `zka_proof_init` / `zka_proof_free` | Allocate / free memory for the proof |

### `zknorm.h` / `zknorm.c`: zk-norm

| Function | What it does |
|---|---|
| `zkn_params_gen` | Chooses the noise size and the commitment sizes |
| `zkn_prove` | **Prover:** creates the noise and commits to it, computes the projection of the secret plus noise, retries with new noise if rejection sampling says so, and builds the new statement and witness |
| `zkn_reduce` | **Verifier:** checks the result is small enough, then builds the same new statement |
| `zkn_proof_init` / `zkn_proof_free` | Allocate / free memory for the proof |

### `test_zkagg.c` and `test_zknorm.c`: tests

They create random examples of different sizes and check that:
1. **Prover and verifier agree:** both end up with the same new statement, and the new witness satisfies it.
2. **Cheating is caught:** a proof that was modified on purpose is rejected.
3. **It connects to LaBRADOR:** the output can be fed into normal LaBRADOR (and, for zk-norm, through zk-agg′ first), and everything still verifies.

`test_zknorm` also prints how often rejection sampling had to retry.

### `Makefile`

Two new targets at the end, `test_zkagg` and `test_zknorm`, so that `make` knows how to build the tests.

## How to run the tests

The code needs a CPU with **AVX-512**.

```bash
make CC=gcc test_zkagg test_zknorm
./test_zkagg
./test_zknorm
```

**No AVX-512 on your CPU?** Compile for it anyway and run the tests with the Intel SDE emulator (slow, but it works):

```bash
CFLAGS="-mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512vbmi -mavx512vbmi2 -mavx512vnni -maes -mvaes" \
  make CC=gcc test_zkagg test_zknorm
sde64 -- ./test_zkagg
sde64 -- ./test_zknorm
```

Each test should end with `all tests passed`.

Lines like `(expected error below) ERROR in verify()` are **normal**. The tests deliberately break proofs to check that broken proofs get rejected. A real problem shows up as a line starting with `FAIL:`.

## What the tests check

- A correct proof is accepted.
- A modified proof is rejected.
- zk-norm → zk-agg′ → LaBRADOR works end to end.
- The number of rejection-sampling retries is reasonable.

## To do

- [x] zk-agg′
- [x] zk-norm
- [ ] Check the retry rate on many runs (a bit higher than expected so far)
- [ ] Discuss the simplifications with the supervisor
- [ ] Π₁ (paper §7.5)
- [ ] Π₂ (paper §7.6)
- [ ] Connect everything and compare speed with plain LaBRADOR
