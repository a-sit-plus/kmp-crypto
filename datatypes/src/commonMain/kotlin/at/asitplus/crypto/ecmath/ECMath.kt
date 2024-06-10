package at.asitplus.crypto.ecmath

import at.asitplus.crypto.datatypes.ECPoint
import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.modular.ModularBigInteger
import kotlin.math.max

/** adds `other` to `this` and returns the result */
/* Algorithm 4 from https://eprint.iacr.org/2015/1060.pdf */
operator fun ECPoint.plus(other: ECPoint): ECPoint {
    require(this.curve == other.curve)
    val b = this.curve.b
    val X1 = this.homX
    val Y1 = this.homY
    val Z1 = this.homZ
    val X2 = other.homX
    val Y2 = other.homY
    val Z2 = other.homZ
    lateinit var t0: ModularBigInteger
    lateinit var t1: ModularBigInteger
    lateinit var t2: ModularBigInteger
    lateinit var t3: ModularBigInteger
    lateinit var t4: ModularBigInteger
    lateinit var X3: ModularBigInteger
    lateinit var Y3: ModularBigInteger
    lateinit var Z3: ModularBigInteger
    /*  1. */ t0 = X1 * X2
    /*  2. */ t1 = Y1 * Y2
    /*  3. */ t2 = Z1 * Z2
    /*  4. */ t3 = X1 + Y1
    /*  5. */ t4 = X2 + Y2
    /*  6. */ t3 = t3 * t4
    /*  7. */ t4 = t0 + t1
    /*  8. */ t3 = t3 - t4
    /*  9. */ t4 = Y1 + Z1
    /* 10. */ X3 = Y2 + Z2
    /* 11. */ t4 = t4 * X3
    /* 12. */ X3 = t1 + t2
    /* 13. */ t4 = t4 - X3
    /* 14. */ X3 = X1 + Z1
    /* 15. */ Y3 = X2 + Z2
    /* 16. */ X3 = X3 * Y3
    /* 17. */ Y3 = t0 + t2
    /* 18. */ Y3 = X3 - Y3
    /* 19. */ Z3 = b * t2
    /* 20. */ X3 = Y3 - Z3
    /* 21. */ Z3 = X3 + X3
    /* 22. */ X3 = X3 + Z3
    /* 23. */ Z3 = t1 - X3
    /* 24. */ X3 = t1 + X3
    /* 25. */ Y3 = b * Y3
    /* 26. */ t1 = t2 + t2
    /* 27. */ t2 = t1 + t2
    /* 28. */ Y3 = Y3 - t2
    /* 29. */ Y3 = Y3 - t0
    /* 30. */ t1 = Y3 + Y3
    /* 31. */ Y3 = t1 + Y3
    /* 32. */ t1 = t0 + t0
    /* 33. */ t0 = t1 + t0
    /* 34. */ t0 = t0 - t2
    /* 35. */ t1 = t4 * Y3
    /* 36. */ t2 = t0 * Y3
    /* 37. */ Y3 = X3 * Z3
    /* 38. */ Y3 = Y3 + t2
    /* 39. */ X3 = t3 * X3
    /* 40. */ X3 = X3 - t1
    /* 41. */ Z3 = t4 * Z3
    /* 42. */ t1 = t3 * t0
    /* 43. */ Z3 = Z3 + t1
    return ECPoint.General.unsafeFromXYZ(curve, X3, Y3, Z3)
}

/** adds `this` to `this` and returns the result */
/* Algorithm 6 from https://eprint.iacr.org/2015/1060.pdf */
fun ECPoint.double(): ECPoint {
    val b = this.curve.b
    val X = this.homX
    val Y = this.homY
    val Z = this.homZ
    lateinit var t0: ModularBigInteger
    lateinit var t1: ModularBigInteger
    lateinit var t2: ModularBigInteger
    lateinit var t3: ModularBigInteger
    lateinit var X3: ModularBigInteger
    lateinit var Y3: ModularBigInteger
    lateinit var Z3: ModularBigInteger
    /*  1. */ t0 = X * X
    /*  2. */ t1 = Y * Y
    /*  3. */ t2 = Z * Z
    /*  4. */ t3 = X * Y
    /*  5. */ t3 = t3 + t3
    /*  6. */ Z3 = X * Z
    /*  7. */ Z3 = Z3 + Z3
    /*  8. */ Y3 = b * t2
    /*  9. */ Y3 = Y3 - Z3
    /* 10. */ X3 = Y3 + Y3
    /* 11. */ Y3 = X3 + Y3
    /* 12. */ X3 = t1 - Y3
    /* 13. */ Y3 = t1 + Y3
    /* 14. */ Y3 = X3 * Y3
    /* 15. */ X3 = X3 * t3
    /* 16. */ t3 = t2 + t2
    /* 17. */ t2 = t2 + t3
    /* 18. */ Z3 = b * Z3
    /* 19. */ Z3 = Z3 - t2
    /* 20. */ Z3 = Z3 - t0
    /* 21. */ t3 = Z3 + Z3
    /* 22. */ Z3 = Z3 + t3
    /* 23. */ t3 = t0 + t0
    /* 24. */ t0 = t3 + t0
    /* 25. */ t0 = t0 - t2
    /* 26. */ t0 = t0 * Z3
    /* 27. */ Y3 = Y3 + t0
    /* 28. */ t0 = Y * Z
    /* 29. */ t0 = t0 + t0
    /* 30. */ Z3 = t0 * Z3
    /* 31. */ X3 = X3 - Z3
    /* 32. */ Z3 = t0 * t1
    /* 33. */ Z3 = Z3 + Z3
    /* 34. */ Z3 = Z3 + Z3
    return ECPoint.General.unsafeFromXYZ(curve, X3, Y3, Z3)
}

inline operator fun ECPoint.unaryPlus() = this
inline operator fun ECPoint.unaryMinus() =
    ECPoint.General.unsafeFromXYZ(curve, homX, -homY, homZ)
inline operator fun ECPoint.Normalized.unaryMinus() =
    ECPoint.Normalized.unsafeFromXY(curve, x, -y)

inline operator fun ECPoint.minus(other: ECPoint) = this+(-other)

// TODO: i'm sure this could be smarter (keyword: "comb")
// i'm also sure this isn't resistant to timing side channels if that is something you care about
operator fun BigInteger.times(point: ECPoint): ECPoint {
    var o = point
    var sum = if (this.bitAt(0)) point else point.curve.IDENTITY
    /* double-and-add */
    for (i in 1L..<this.bitLength()) {
        /* we double o on each iteration (it is (2^i)*point) */
        o = o.double()
        /* and decide whether to add it based on the bit */
        if (this.bitAt(i)) sum += o
    }
    return sum
}

inline operator fun Int.times(point: ECPoint) =
    BigInteger.fromInt(this).times(point)
inline operator fun Long.times(point: ECPoint) =
    BigInteger.fromLong(this).times(point)
inline operator fun UInt.times(point: ECPoint) =
    BigInteger.fromUInt(this).times(point)
inline operator fun ULong.times(point: ECPoint) =
    BigInteger.fromULong(this).times(point)

inline operator fun ModularBigInteger.times(point: ECPoint): ECPoint {
    require(this.modulus == point.curve.order)
    return this.residue.times(point)
}

/* these are intentionally not operator functions! */
inline fun ECPoint.times(v: BigInteger) = v * this
inline fun ECPoint.times(v: ModularBigInteger) = v * this
inline fun ECPoint.times(v: Int) = v * this
inline fun ECPoint.times(v: UInt) = v * this
inline fun ECPoint.times(v: Long) = v * this
inline fun ECPoint.times(v: ULong) = v * this

/** computes uG+vQ */
fun straussShamir(u: BigInteger, G: ECPoint, v: BigInteger, Q: ECPoint): ECPoint {
    val H = G+Q
    val uL = u.bitLength()
    val vL = v.bitLength()
    var i = max(uL,vL).toLong()-1
    var R = if(uL > vL) G else if (uL < vL) Q else H
    while (--i >= 0) {
        R = R.double()
        val b = u.bitAt(i)
        val c = v.bitAt(i)
        if (b && c) R += H
        else if (b) R += G
        else if (c) R += Q
    }
    return R
}

/** computes pQ in constant time */
fun montgomeryMul(k: BigInteger, P: ECPoint): ECPoint {
    var R0 = P
    var R1 = P.double()
    var i = k.bitLength().toLong()-1
    while (--i >= 0) {
        if (k.bitAt(i)) {
            R0 = (R0+R1)
            R1 = R1.double()
        } else {
            R1 = (R0+R1)
            R0 = R0.double()
        }
    }
    return R0
}
