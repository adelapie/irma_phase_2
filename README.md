irma_phase_2
============

Implementation of complex NIPKs in embedded devices.

#### Optimizations

- fortuna-only: Utilization of a PRNG for recomputing
pseudorandomness during the generation of both t-/s-values.
- (dev) prime-encoding (AND).

#### Protocol extensions

- nyms: Idemix standard pseudonyms.
- dnym: Idemix standard psudonyms in combination with domain ones.

#### Multi-credential proofs

- eq_proof_a: Equality proof of representation across n credentials (2).
- eq_proof_b: Equality proof of representation across 2 credentials.
- eq_proof_c: Equality proof of representation via prime encoding.

### How to run the examples

#### Client-side

The terminal code is based on CHARM and must be installed before running
pirma.py:

```
git clone https://github.com/JHUISI/charm
cd charm
./configure.sh
make install (may require super-user privileges)
```

Then, download one of the clients and run pirma.py.

```
git clone https://github.com/adelapie/irma_phase_2
cd terminal/t_[example]
python prima.py
```

In irma/prover.py there are usually two group of APDUs for performing
the best case if terms of number of operations (reveal all) and hiding all
the attributes.

#### Card-side
