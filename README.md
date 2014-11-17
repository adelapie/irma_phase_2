Pushing the limits of the IRMA card
===================================

Implementation of complex NIPKs on embedded devices.

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

The ```idemix/``` directory contains an implementation in python of the selective
disclosure primitives and issuing of the Idemix specification [1].

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

These modifications run on the implementation of the IRMA card developed by Pim Vullers [2].

#### Optimizations

- Utilization of a PRNG for recomputing
pseudorandomness during the generation of both t-/s-values.
https://github.com/adelapie/irma_phase_2/tree/master/selective_disclosure
- prime-encoding:
	* AND https://github.com/adelapie/irma_phase_2/tree/master/AND (ph: hide all, pr: reveal n attributes)
	* NOT https://github.com/adelapie/irma_phase_2/tree/master/NOT (pre: precomputation of the values of the
diophantine equation, euclid: solving the diophantine equation at run time)
	* OR https://github.com/adelapie/irma_phase_2/tree/master/OR (case_1: one attribute
belongs to a list of constants)

#### Protocol extensions

- nyms: Idemix standard pseudonyms https://github.com/adelapie/irma_phase_2/tree/master/nym
- dnym: Idemix standard psudonyms in combination with domain ones https://github.com/adelapie/irma_phase_2/tree/master/dnym

#### Multi-credential proofs

- eq_proof: Equality proof of representation. In this example ```pirma.py``` first issues two
credentials and then perform an equality proof of representation based on their master secret.
https://github.com/adelapie/irma_phase_2/tree/master/eq_proof

### References

- Antonio de la Piedra, Jaap-Henk Hoepman, and Pim Vullers, Towards a Full-Featured Implementation of Attribute Based Credentials on Smart Card. In A. Kiayias and D. Gritzali, editors, 13th Int. Conf. on Cryptology and Network Security - CANS 2014, Heraklion, Crete, Greece, October 22-24 2014.
- Idemix specification: http://www.zurich.ibm.com/security/idemix/
- The IRMA card: https://github.com/credentials/irma_card

