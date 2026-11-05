# Chronos in the Octet Cage

| | |
|---|---|
| **Challenge ID** | `r31awAEk` |
| **Category** | Cryptography |
| **Flag format** | `FLAG{...}` |

## Premise

> Partial keys, broken transcripts, and a custom mixer. Find the prime factors
> and unlock the vault.

The challenge defines a custom 4-dimensional bilinear "mixer" over `Z_N` and
publishes telemetry from it, together with an RSA modulus `N`, a decoy
`e_aux`/`hint_d` pair, and an encrypted flag. The mixer is actually an
associative algebra whose norm form makes the hidden small errors factor `N`.

## Artifacts

```
d24d9ff3bb9247dc8c0f2b79952cbbf4.zip
chronos_in_the_octet_cage/chall.py     reference generator
chronos_in_the_octet_cage/output.txt   N, e, e_aux, hint_d, telemetry[8], C_flag
```

The published values:

* `N` — 1024-bit RSA modulus (`p`, `q` 512-bit each),
* `e = 65537`,
* `e_aux`, `hint_d` — decoy partial-key exposure (450 unknown bits; a
  Boneh–Durfee dead end by design),
* eight telemetry records `{W1, W2, Z}`,
* `C_flag` — the flag encrypted in the mixer algebra.

## The algebra

The structure tensor `GAMMA[k][a][b]` defines

```python
def mix(X, Y, N):
    return [sum(GAMMA[k][a][b]*X[a]*Y[b]
                for a in range(4) for b in range(4)) % N
            for k in range(4)]
```

Key properties verified in the solve:

1. **Associative** (checked on random small vectors over the integers).
2. The left-multiplication matrix `L_X` (`Y -> mix(X,Y)`) has

   ```
   det(L_X) = N(X)^2
   ```

   where

   ```
   N(X) = 20x0^2 - 10x0x1 + 50x0x2 - 34x0x3
                + 3x1^2 - 14x1x2 + 8x1x3
                + 35x2^2 - 44x2x3 + 15x3^2
   ```

   is a quadratic form. Because `det` is multiplicative and `det(L_X)` is a
   perfect square, `N(XY) = N(X)N(Y)`. Also `N(1,0,0,1) = 20 - 34 + 15 = 1`,
   so this is a norm form with a unit.

The algebra is thus isomorphic (via CRT over `N = pq`) to a product of two
4-dimensional matrix-like algebras; its unit group has order

```
|G| = (p^2 - 1)(p^2 - p) * (q^2 - 1)(q^2 - q)
```

which is exactly `|GL_2(F_p)| * |GL_2(F_q)|`.

## Step 1 — recover the hidden vectors `U_i` from telemetry

The generator builds, for each `i`:

```
U_i = (p * R_i + E_i) mod N        # R_i 512-bit, E_i 60-bit per coordinate
W1  = mix(A_i, B_i)
W2  = mix(B_i, C_i)
Z   = mix(mix(mix(mix(B_{i+1}, U_i), A_i), C_{i+1}), B_i)
```

Because `N(.)` is multiplicative:

```
N(Z) = N(B_{i+1}) N(U_i) N(A_i) N(C_{i+1}) N(B_i)
N(W1_i) = N(A_i) N(B_i)
N(W2_{i+1}) = N(B_{i+1}) N(C_{i+1})
```

so

```
N(U_i) = N(Z_i) * inverse(N(W1_i) * N(W2_{i+1}))  mod N
```

No secret `A`, `B`, `C` is needed — the norm cancels them.

## Step 2 — factor `N` with Coppersmith's unknown-divisor attack

Write `U_i = p R_i + E_i`. Expanding the quadratic norm:

```
N(U_i) = p^2 N(R_i) + p * B(R_i, E_i) + N(E_i)
       ≡ N(E_i)  (mod p)
```

So `p` divides `a_i - r_i`, where

* `a_i = N(U_i) mod N` (known, ~1020 bits),
* `r_i = N(E_i)` is **small**: entries of `E_i` are 60-bit, so `r_i < 2^135`.

`p` is an unknown divisor of `N` of size `N^0.5` (`beta = 0.49`). This is the
classic Howgrave-Graham/Coppersmith univariate setting: find the small root
`r` of `f(x) = x - a_i` modulo the unknown divisor `p`.

Implementation used:

* exact integer LLL (`lll_exact.py`) because stock LLL libraries choked on the
  1024-bit lattice,
* `coppersmith_howgrave_univariate(f, N, beta=0.49, m=2, t=2, X=2^135)`,
* candidate root `r` validated by `gcd(a_i - r, N)`.

The attack succeeded with `(m, t) = (2, 2)`. Recovered factors:

```
p = 7924733393877564799725566672878426987964073184918530110204841058935075302329030941148750352211402100523960212039475947603386372915856793403478731355473061
q = 7263154262815757547574623347886074596667145192535458084138724588398168710701506231419883703603003584837892007283858196777543686437311246851340469791784221
```

(`p*q == N` verified.)

## Step 3 — invert the `e`-th power in the algebra

The flag is encoded as four 128-bit chunks with random high bits:

```
F[k] = int(flag[15k:15k+15]) | (random_256 << 128)
C_flag = F^e   (repeated mixer squaring/multiplying)
```

Since the algebra is finite and `gcd(e, |G|) = 1`, the map `x -> x^e` is a
bijection. Compute

```
d = e^{-1} mod |G|
F = C_flag^d
```

and verify `F^e == C_flag`. Then each component modulo `2^128` yields the
15-byte flag chunk (the random high bits vanish):

```python
F = mix_pow(C_flag, pow(e, -1, G), N)
out = b""
for v in F:
    out += (v % (1 << 128)).to_bytes(16, "big")[1:]   # drop the leading zero
print(out.rstrip(b"\x00"))
```

Output:

```
FLAG{ab3l1an_n0rm_unr4v3ls_scr4mbl3d_qu4t3rn10n_t3ns0r_9f2a}
```

## Tools & Methodology

**Tools:** Python 3, exact-integer LLL (`lll_exact.py`), Howgrave-Graham /
Coppersmith univariate `small_roots` with `(m,t)=(2,2)`, finite-field algebra
over the four-dimensional normed algebra.

**Method:**

1. Used multiplicativity of the algebra norm to cancel the unknown `A,B,C` and
   recover `N(U_i)` from each telemetry record.
2. Wrote `U_i = pR_i + E_i` with 60-bit `E_i`, formed `f(x)=x-N(U_i) mod N`, and
   ran Coppersmith's unknown-divisor attack (`beta≈0.49`, `X=2^135`) to split
   `N` into `p` and `q`; verified `p*q == N`.
3. Computed `|G|=(p²-1)(p²-p)(q²-1)(q²-q)`, inverted `e` modulo `|G|`, applied
   the inverse power to the flag ciphertext, and stripped the random high bits.

## Flag

```
FLAG{ab3l1an_n0rm_unr4v3ls_scr4mbl3d_qu4t3rn10n_t3ns0r_9f2a}
```

## Takeaway

Two independent mistakes combine:

1. The custom algebra leaks a **multiplicative norm** of secret-blinded values.
   Any time a "mixer" is an associative composition algebra, its norm is a
   homomorphism, and products of secrets cancel.
2. `U_i = p*R_i + E_i` with a 60-bit error is a **partial key exposure** style
   approximate common divisor. Coppersmith's method recovers `p` once the error
   is below `N^(1/4)`-ish in the univariate unknown-divisor setting.

The decoy `hint_d` (450 unknown bits) is a deliberate distraction — the real
break is the algebra norm, not partial-`d` lattice reduction.
