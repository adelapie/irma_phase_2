irma_phase_2
============

Implementation of complex NIPKs in embedded devices.

### How to run the examples

#### Client-side

The terminal code is based on CHARM and must be installed before running
pirma.py:

```
git clone https://github.com/JHUISI/charm
cd charm
./configure.sh
make install (may require root privileges)
```

Then, download one of the clients and run pirma.py.

```
git clone https://github.com/adelapie/irma_phase_2
cd terminal/t_[example]
python prima.py
```

The performance analysis can be done redirecting the output of the client to
a separate text file and then accumulating the transaction time per APDU using 
latency.sh or simply by redirecting the client to awk e.g. ```awk '{ sum += $3 } END { print sum }'```.

In irma/prover.py there are usually two group of APDUs for performing
the best case if terms of number of operations (reveal all) and hiding all
the attributes.

#### Card-side

These examples are based on MULTOS cards that can be ordered
through http://www.multosinternational.com/. Compiling and loading the code 
in the card must be done using SmartDeck and MUtil. Both applications can be 
downloaded from http://www.multos.com/developer_centre/tools_and_sdk/.

#### Optimizations

- fortuna-only: Utilization of a PRNG for recomputing
pseudorandomness during the generation of both t-/s-values.
- (dev) prime-encoding (AND).

#### Protocol extensions

- nyms: Idemix standard pseudonyms.
- dnym: Idemix standard psudonyms in combination with domain ones.

#### Multi-credential proofs

- eq_proof: Equality proof of representation
