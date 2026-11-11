"""Pairing-only mutations of a saved Aztec v6 HONK_ZK (noir-recursive) proof.

An in-circuit recursive verifier (std::verify_proof_with_type, proof type 6) checks
the transcript, sumcheck and the key hash, and returns two pairing points. It does
not compute the pairing. The pairing points travel to the parent (Ultra DefaultIO
or Mega AppIO, then the kernel and Chonk), and only the final pairing check rejects
a proof whose last commitments are valid curve points with the wrong value.

The proof ends with two commitments of the batched opening: Shplonk:Q, then KZG:W.
Each point is four fields (x_lo, x_hi, y_lo, y_hi) with 136-bit low limbs. The
mutations below replace one of them with a different point ON the curve, so that
witness generation and every in-circuit check still pass and only the pairing
check can reject the proof. A point off the curve (for example a changed limb) is
rejected earlier, when the verifier builds the point, so it does not test the
deferred pairing check.

This module only rewrites saved proof fields. It never proves or verifies.
"""

# BN254 base field (curve coordinates) and scalar field (proof field elements).
Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
PROOF_FIELDS = 458
LIMB_BITS = 136
LIMB = (1 << LIMB_BITS) - 1
GENERATOR = (1, 2)
KZG_W = slice(PROOF_FIELDS - 4, PROOF_FIELDS)
SHPLONK_Q = slice(PROOF_FIELDS - 8, PROOF_FIELDS - 4)


def point(fields):
    """Decode four limb fields into an affine point; reject a noncanonical encoding."""
    x_lo, x_hi, y_lo, y_hi = fields
    if max(x_lo, y_lo) > LIMB:
        raise ValueError("Low limb exceeds 136 bits")
    x, y = x_lo + (x_hi << LIMB_BITS), y_lo + (y_hi << LIMB_BITS)
    if not (x < Q and y < Q):
        raise ValueError("Coordinate is not a canonical base-field element")
    return x, y


def encode(p):
    return [p[0] & LIMB, p[0] >> LIMB_BITS, p[1] & LIMB, p[1] >> LIMB_BITS]


def on_curve(p):
    return (p[1] * p[1] - p[0] ** 3 - 3) % Q == 0


def add(a, b):
    """Affine addition on y^2 = x^3 + 3 for points that are not inverse."""
    if a == b:
        slope = 3 * a[0] * a[0] * pow(2 * a[1], -1, Q) % Q
    else:
        slope = (b[1] - a[1]) * pow(b[0] - a[0], -1, Q) % Q
    x = (slope * slope - a[0] - b[0]) % Q
    return x, (slope * (a[0] - x) - a[1]) % Q


def pairing_only_mutations(proof):
    """Return {name: proof} where each proof differs only in one opening point.

    Every replacement point is on the curve and differs from the original, so a
    verifier that dropped the deferred pairing check would accept the proof.
    """
    proof = [int(x) for x in proof]
    if len(proof) != PROOF_FIELDS or any(not 0 <= x < R for x in proof):
        raise ValueError("Expected 458 canonical proof fields")
    w, q = point(proof[KZG_W]), point(proof[SHPLONK_Q])
    if not (on_curve(w) and on_curve(q)):
        raise ValueError("Saved opening commitments are not on the curve")
    replacements = {
        "kzg-w-generator": (KZG_W, GENERATOR),
        "kzg-w-negated": (KZG_W, (w[0], (Q - w[1]) % Q)),
        "kzg-w-doubled": (KZG_W, add(w, w)),
        "shplonk-q-generator": (SHPLONK_Q, GENERATOR),
    }
    result = {}
    for name, (where, replacement) in replacements.items():
        original = point(proof[where])
        if replacement == original or not on_curve(replacement):
            raise ValueError("Replacement must be a different curve point: " + name)
        changed = list(proof)
        changed[where] = encode(replacement)
        result[name] = changed
    return result
