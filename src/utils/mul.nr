use crate::utils::arrayX::ArrayX;
use crate::BigNum;

/**
  * @brief schoolbook multiplication of 2 N-length arrays, no reductions
  **/
pub fn schoolbook_mult<let N: u32>(a: [Field; N], b: [Field; N]) -> ArrayX<Field, N, 2> {
    let mut res = ArrayX { segments: [[0; N], [0; N]] };
    for i in 0..N {
        for j in 0..N {
            res.add_assign(i + j, a[i] * b[j]);
        }
    }
    res
}

/**
  * @brief simple addition of limbs of 2 N-length arrays, no reductions
  **/
fn add_arrays<N>(a: [Field; N], b: [Field; N]) -> [Field; N] {
    let mut res = [0; N];
    for i in 0..N {
        res[i] = a[i]+b[i];
    }
    res
}

/**
  * @brief simple subtraction of limbs of 2 N-length arrays, no reductions
  * @description This directly subtracts a[i]-b[i]-c[i] for all N limbs,
  *              thus some limbs might have a "negative" value which has wrapped
  *              around in the Field type.
  **/
fn subtract_arrays<N>(
    a: ArrayX<Field, N, 2>,
    b: ArrayX<Field, N, 2>,
    c: ArrayX<Field, N, 2>
) -> ArrayX<Field, N, 2> {
    let mut res = ArrayX { segments: [[0; N], [0; N]] };
    for i in 0..2 {
        for j in 0..N {
            res.segments[i][j] = a.segments[i][j] - b.segments[i][j] - c.segments[i][j];
        }
    }
    res
}

/**
  * @brief For karatsuba multiplication, returns values r0, r1, r2
  *        which represent the lower, (overlapping) middle and higher limbs of the result
  * @description: this computes for a, b, split in the middle as a = [a_lo, a_hi], b = [b_lo, b_hi]:
  *               (If the length is odd, the lower half is 1 smaller than the higher half)
  *               r0 = a_lo * b_lo
  *               r2 = a_hi * b_hi
  *               r1 = a_lo*b_hi + a_hi*b_lo
  * @param a: input byte array, length N
  * @param b: input byte array, length N
  * @param odd: bool whether N is odd
  * 
  * Note that M is the length of the larger half. This needs to be a numeric generic, in order
  * to create an array of that length that will be accepted by the compiler
  **/
fn get_r012_karatsuba<N, M>(
    a: [Field; N],
    b: [Field; N],
    odd: bool
) -> (ArrayX<Field, M, 2>, ArrayX<Field, M, 2>, ArrayX<Field, M, 2>) {
    // Initialize lo/hi arrays of same length, even if the lower half is shorter
    // this is for consequent functions
    // a = [a_lo, a_hi], b = [b_lo, b_hi]
    let mut a_lo = [0; M];
    let mut a_hi = [0; M];
    let mut b_lo = [0; M];
    let mut b_hi = [0; M];

    let mut len_lo = M;
    if odd {
        len_lo -= 1;
    }
    for i in 0..len_lo {
        a_lo[i] = a[i];
        b_lo[i] = b[i];
    }
    for i in len_lo..N {
        a_hi[i-len_lo] = a[i];
        b_hi[i-len_lo] = b[i];
    }

    // The following is calculated:
    // r0 = a_lo * b_lo
    // r2 = a_hi * b_hi
    // r1 = (a_lo+a_hi)(b_lo+b_hi) - r0 - r2
    //    = a_lo*b_lo + a_lo*b_hi + a_hi*b_lo + a_hi*b_hi - a_lo*b_lo - a_hi*b_hi
    //    = a_lo*b_hi + a_hi*b_lo

    // a_lo, b_lo, a_hi, b_hi have (M of M-1) limbs of 120 bits
    // r0, r2 have 2M-1 limbs of 240+log(2M-1) bits
    let r0: ArrayX<Field, M, 2> = schoolbook_mult(a_lo, b_lo);
    let r2: ArrayX<Field, M, 2> = schoolbook_mult(a_hi, b_hi);

    // added_a, added_b have (M of M-1) limbs of 121 bits
    let added_a = add_arrays(a_lo, a_hi);
    let added_b = add_arrays(b_lo, b_hi);
    // r1 has 2M-1 limbs of 242+log(2M-1) bits
    let mut r1: ArrayX<Field, M, 2> = schoolbook_mult(added_a, added_b);
    // This subtraction gives no issues if used in combination with combining these results as follows:
    // [r0_lo, r0_hi + r1_lo, r1_hi + r2_lo, r2_hi]
    // because all limbs will be positive, even if in intermediate value r1 there may be "negative" values
    r1 = subtract_arrays(r1, r0, r2);

    (r0, r1, r2)
}

/**
  * @brief For karatsuba multiplication, correctly combines values r0, r1, r2 into the result
  * @description: r0 are the lower limbs, r2 the higher limbs, and r1 the "middle limbs"
  *               that overlap partially with both lower & higher parts
  *
  * @param r0: 2 arrays of length M, contains value a_lo * b_lo
  * @param r1: 2 arrays of length M, contains value a_lo*b_hi + a_hi*b_lo
  * @param r2: 2 arrays of length M, contains value a_hi * b_hi
  **/
fn combine_res_karatsuba<N, M>(
    r0: ArrayX<Field, M, 2>,
    r1: ArrayX<Field, M, 2>,
    r2: ArrayX<Field, M, 2>,
    odd: bool
) -> ArrayX<Field, N, 2> {
    // Result has 2*N limbs, of which the last will be 0
    let mut res = ArrayX { segments: [[0; N], [0; N]] };

    let mut len_lo = M;
    if odd {
        len_lo -= 1;
    }

    // r0 -> low terms, r1 -> middle terms, r2 -> high terms
    // res = [r0_lo, r0_hi + r1_lo, r1_hi + r2_lo, r2_hi]
    for i in 0..N {
        res.add_assign(i, r0.get(i));
        res.add_assign(i + len_lo, r1.get(i));
        res.add_assign(i + len_lo + len_lo, r2.get(i));
    }
    res
}

/**
  * @brief Karatsuba multiplication fixed for 9 limbs
  * @description This 1 level Karatsuba, the next level does schoolbook mult
  **/
pub fn karatsuba_mult_9(a: [Field; 9], b: [Field; 9]) -> ArrayX<Field, 9, 2> {
    let (r0, r1, r2): (ArrayX<Field, 5, 2>, ArrayX<Field, 5, 2>, ArrayX<Field, 5, 2>) = get_r012_karatsuba(a, b, true);
    combine_res_karatsuba(r0, r1, r2, true)
}

/**
  * @brief Karatsuba multiplication fixed for 18 limbs
  * @description This is 3 level Karatsuba, it performs in recursion:
  *              Karatsuba-18 -> Karatsuba-9 -> Schoolbook
  **/
pub fn karatsuba_mult_18(a: [Field; 18], b: [Field; 18]) -> ArrayX<Field, 18, 2> {
    let mut a_lo = [0; 9];
    let mut a_hi = [0; 9];
    let mut b_lo = [0; 9];
    let mut b_hi = [0; 9];

    let len_lo = 9;
    for i in 0..len_lo {
        a_lo[i] = a[i];
        b_lo[i] = b[i];
    }
    for i in len_lo..18 {
        a_hi[i-len_lo] = a[i];
        b_hi[i-len_lo] = b[i];
    }

    let r0: ArrayX<Field, 9, 2> = karatsuba_mult_9(a_lo, b_lo);
    let r2: ArrayX<Field, 9, 2> = karatsuba_mult_9(a_hi, b_hi);

    let added_a = add_arrays(a_lo, a_hi);
    let added_b = add_arrays(b_lo, b_hi);
    let mut r1: ArrayX<Field, 9, 2> = karatsuba_mult_9(added_a, added_b);
    r1 = subtract_arrays(r1, r0, r2);

    combine_res_karatsuba(r0, r1, r2, false)
}

/**
  * @brief Karatsuba multiplication fixed for 35 limbs
  * @description This is 3 level Karatsuba, it performs in recursion:
  *              Karatsuba-35 -> Karatsuba-18 -> Karatsuba-9 -> Schoolbook
  **/
pub fn karatsuba_mult_35(a: [Field; 35], b: [Field; 35]) -> ArrayX<Field, 35, 2> {
    let mut a_lo = [0; 18];
    let mut a_hi = [0; 18];
    let mut b_lo = [0; 18];
    let mut b_hi = [0; 18];

    let len_lo = 17;
    for i in 0..len_lo {
        a_lo[i] = a[i];
        b_lo[i] = b[i];
    }
    for i in len_lo..35 {
        a_hi[i-len_lo] = a[i];
        b_hi[i-len_lo] = b[i];
    }

    let r0: ArrayX<Field, 18, 2> = karatsuba_mult_18(a_lo, b_lo);
    let r2: ArrayX<Field, 18, 2> = karatsuba_mult_18(a_hi, b_hi);

    let added_a = add_arrays(a_lo, a_hi);
    let added_b = add_arrays(b_lo, b_hi);
    let mut r1: ArrayX<Field, 18, 2> = karatsuba_mult_18(added_a, added_b);
    r1 = subtract_arrays(r1, r0, r2);

    combine_res_karatsuba(r0, r1, r2, false)
}
