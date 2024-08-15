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
            let new_term =  a.segments[i][j] - b.segments[i][j] - c.segments[i][j]; 
            // std::as_witness(new_term);
            res.segments[i][j] = new_term;
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
  * @brief Combined function for Karatsuba multiplication, returns the result of the multiplication
  *        by computing r0, r1, r2 and then combining them into the final result.
  * @description: This function computes the values r0, r1, r2 for a and b, where:
  *               r0 = a_lo * b_lo
  *               r2 = a_hi * b_hi
  *               r1 = (a_lo + a_hi) * (b_lo + b_hi) - r0 - r2
  *               Then, it combines these values to produce the final result.
  * @param a: input byte array, length N
  * @param b: input byte array, length N
  * @param odd: bool indicating whether N is odd
  * 
  * @return The result of the Karatsuba multiplication as an array.
  **/
// fn karatsuba_mult_combined<let N: u64, let M: u64>(
//     a: [Field; N],
//     b: [Field; N],
//     odd: bool
// ) -> ArrayX<Field, N, 2> {
//     // Initialize lo/hi arrays
//     let mut a_lo = [0; M];
//     let mut a_hi = [0; M];
//     let mut b_lo = [0; M];
//     let mut b_hi = [0; M];

//     let mut len_lo = M;
//     if odd {
//         len_lo -= 1;
//     }
//     for i in 0..len_lo {
//         a_lo[i] = a[i];
//         b_lo[i] = b[i];
//     }
//     for i in len_lo..N {
//         a_hi[i-len_lo] = a[i];
//         b_hi[i-len_lo] = b[i];
//     }

//     // Calculate r0, r1, r2
//     let r0: ArrayX<Field, M, 2> = schoolbook_mult(a_lo, b_lo);
//     let r2: ArrayX<Field, M, 2> = schoolbook_mult(a_hi, b_hi);

//     // Directly add arrays
//     let mut added_a = [0; M];
//     let mut added_b = [0; M];
//     for i in 0..M {
//         added_a[i] = a_lo[i] + a_hi[i];
//         added_b[i] = b_lo[i] + b_hi[i];
//     }

//     let mut r1: ArrayX<Field, M, 2> = schoolbook_mult(added_a, added_b);

//     // Directly subtract arrays
//     let mut res = ArrayX { segments: [[0; N], [0; N]] };
//     for i in 0..2 {
//         for j in 0..M {
//             let new_term = r1.segments[i][j] - r0.segments[i][j] - r2.segments[i][j];
//             res.segments[i][j] = new_term;
//         }
//     }

//     // Combine r0, r1, r2 into the final result
//     for i in 0..len_lo {
//         res.add_assign(i, r0.get(i));
//         res.add_assign(i + len_lo, r1.get(i));
//         res.add_assign(i + len_lo + len_lo, r2.get(i));
//     }

//     res
// }


/**
  * @brief Karatsuba multiplication fixed for 9 limbs
  * @description This 1 level Karatsuba, the next level does schoolbook mult
  **/
pub fn karatsuba_mult_9(a: [Field; 9], b: [Field; 9]) -> ArrayX<Field, 9, 2> {
    // Initialize lo/hi arrays
    let mut a_lo = [0; 5];
    let mut a_hi = [0; 5];
    let mut b_lo = [0; 5];
    let mut b_hi = [0; 5];

    let mut len_lo = 4;
    for i in 0..len_lo {
        a_lo[i] = a[i];
        b_lo[i] = b[i];
    }
    for i in len_lo..9 {
        a_hi[i-len_lo] = a[i];
        b_hi[i-len_lo] = b[i];
    }

    // Calculate r0, r1, r2
    // r0 = a_lo * b_lo
    // r2 = a_hi * b_hi
    // r1 = a_lo*b_hi + a_hi*b_lo
    let r0: ArrayX<Field, 5, 2> = schoolbook_mult(a_lo, b_lo);
    let r2: ArrayX<Field, 5, 2> = schoolbook_mult(a_hi, b_hi);

    let mut added_a = [0; 5];
    let mut added_b = [0; 5];
    for i in 0..5 {
        added_a[i] = a_lo[i] + a_hi[i];
        added_b[i] = b_lo[i] + b_hi[i];
    }

    let mut r1: ArrayX<Field, 5, 2> = schoolbook_mult(added_a, added_b);

    // r1 = (a_lo+a_hi)(b_lo+b_hi) - r0 - r2
    //    = a_lo*b_lo + a_lo*b_hi + a_hi*b_lo + a_hi*b_hi - a_lo*b_lo - a_hi*b_hi
    //    = a_lo*b_hi + a_hi*b_lo
    for i in 0..2 {
        for j in 0..5 {
            let new_term = r1.segments[i][j] - r0.segments[i][j] - r2.segments[i][j];
            // std::as_witness(new_term); 
            // 34961 for U1024 with above line
            // 34410 for U1024 WITHOUT above line <- optimal
            
            // this is an improvement for U2048?
            // 100014 for U2048 with above line <- optimal
            // 104264 for U2048 WITHOUT above line

            // this is an improvement for U4096?
            // 317238 for U4096 with above line
            // 364712 for U4096 WITHOUT above line
            r1.segments[i][j] = new_term;
        }
    }

    let mut res = ArrayX { segments: [[0; 9], [0; 9]] };
    

    // Combine r0, r1, r2 into the final result
    for i in 0..9 {
        res.add_assign(i, r0.get(i));
        res.add_assign(i + len_lo, r1.get(i));
        res.add_assign(i + len_lo + len_lo, r2.get(i));
    }

    res
}

// /**
//   * @brief Karatsuba multiplication fixed for 18 limbs
//   * @description This is 3 level Karatsuba, it performs in recursion:
//   *              Karatsuba-18 -> Karatsuba-9 -> Schoolbook
//   **/
// pub fn karatsuba_mult_18(a: [Field; 18], b: [Field; 18]) -> ArrayX<Field, 18, 2> {
//     let mut a_lo = [0; 9];
//     let mut a_hi = [0; 9];
//     let mut b_lo = [0; 9];
//     let mut b_hi = [0; 9];

//     let len_lo = 9;
//     for i in 0..len_lo {
//         a_lo[i] = a[i];
//         b_lo[i] = b[i];
//     }
//     for i in len_lo..18 {
//         a_hi[i-len_lo] = a[i];
//         b_hi[i-len_lo] = b[i];
//     }

//     let r0: ArrayX<Field, 9, 2> = karatsuba_mult_9(a_lo, b_lo);
//     let r2: ArrayX<Field, 9, 2> = karatsuba_mult_9(a_hi, b_hi);

//     let added_a = add_arrays(a_lo, a_hi);
//     let added_b = add_arrays(b_lo, b_hi);
//     let mut r1: ArrayX<Field, 9, 2> = karatsuba_mult_9(added_a, added_b);
//     r1 = subtract_arrays(r1, r0, r2);

//     combine_res_karatsuba(r0, r1, r2, false)
// }
pub fn karatsuba_mult_18(a: [Field; 18], b: [Field; 18]) -> ArrayX<Field, 18, 2> {
    // Initialize lo/hi arrays
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

    // Calculate r0, r1, r2
    let r0: ArrayX<Field, 9, 2> = karatsuba_mult_9(a_lo, b_lo);
    let r2: ArrayX<Field, 9, 2> = karatsuba_mult_9(a_hi, b_hi);

    // Directly add arrays
    let mut added_a = [0; 9];
    let mut added_b = [0; 9];
    for i in 0..9 {
        added_a[i] = a_lo[i] + a_hi[i];
        added_b[i] = b_lo[i] + b_hi[i];
    }

    let mut r1: ArrayX<Field, 9, 2> = karatsuba_mult_9(added_a, added_b);

    // Directly subtract arrays
    for i in 0..2 {
        for j in 0..9 {
          // No improvement in gatecount when using this value directly in next for loops
            let new_term = r1.segments[i][j] - r0.segments[i][j] - r2.segments[i][j];
            // std::as_witness(new_term); // TODO benchmark for length 18 and 35
            r1.segments[i][j] = new_term;
        }
    }
    let mut res = ArrayX { segments: [[0; 18], [0; 18]] };

    // Combine r0, r1, r2 into the final result
    for i in 0..18 {
        // No improvement in gatecount replacing add_assign with direct assignment to segment element
        // No improvement in gatecount replacing .get with direct assignment
        res.add_assign(i, r0.get(i));
        res.add_assign(i + len_lo, r1.get(i));
        res.add_assign(i + len_lo + len_lo, r2.get(i));
    }

    res
}


// EXPERIMENT: mult, ACIR OP: 381687, Circuit Size: 540581

// /**
//   * @brief Karatsuba multiplication fixed for 35 limbs
//   * @description This is 3 level Karatsuba, it performs in recursion:
//   *              Karatsuba-35 -> Karatsuba-18 -> Karatsuba-9 -> Schoolbook
//   **/
// pub fn karatsuba_mult_35(a: [Field; 35], b: [Field; 35]) -> ArrayX<Field, 35, 2> {
//     let mut a_lo = [0; 18];
//     let mut a_hi = [0; 18];
//     let mut b_lo = [0; 18];
//     let mut b_hi = [0; 18];

//     let len_lo = 17;
//     for i in 0..len_lo {
//         a_lo[i] = a[i];
//         b_lo[i] = b[i];
//     }
//     for i in len_lo..35 {
//         a_hi[i-len_lo] = a[i];
//         b_hi[i-len_lo] = b[i];
//     }

//     let r0: ArrayX<Field, 18, 2> = karatsuba_mult_18(a_lo, b_lo);
//     let r2: ArrayX<Field, 18, 2> = karatsuba_mult_18(a_hi, b_hi);

//     let added_a = add_arrays(a_lo, a_hi);
//     let added_b = add_arrays(b_lo, b_hi);
//     let mut r1: ArrayX<Field, 18, 2> = karatsuba_mult_18(added_a, added_b);
//     r1 = subtract_arrays(r1, r0, r2);

//     combine_res_karatsuba(r0, r1, r2, false)
// }

// EXPERIMENT: mult, ACIR OP: 318627, Circuit Size: 364712
pub fn karatsuba_mult_35(a: [Field; 35], b: [Field; 35]) -> ArrayX<Field, 35, 2> {
    // Initialize lo/hi arrays
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

    // Calculate r0, r1, r2
    let r0: ArrayX<Field, 18, 2> = karatsuba_mult_18(a_lo, b_lo);
    let r2: ArrayX<Field, 18, 2> = karatsuba_mult_18(a_hi, b_hi);

    let mut added_a = [0; 18];
    let mut added_b = [0; 18];
    for i in 0..18 {
        added_a[i] = a_lo[i] + a_hi[i];
        added_b[i] = b_lo[i] + b_hi[i];
    }

    let mut r1: ArrayX<Field, 18, 2> = karatsuba_mult_18(added_a, added_b);

    for i in 0..2 {
        for j in 0..18 {
            let new_term = r1.segments[i][j] - r0.segments[i][j] - r2.segments[i][j];
            // std::as_witness(new_term); // todo test whether this is an improvement
            r1.segments[i][j] = new_term;
        }
    }
    let mut res = ArrayX { segments: [[0; 35], [0; 35]] };

    for i in 0..18 {
        res.add_assign(i, r0.segments[0][i]);
        res.add_assign(i + len_lo, r1.segments[0][i]);
        res.add_assign(i + len_lo + len_lo, r2.segments[0][i]);
    }

    for i in 18..35 {
        res.add_assign(i, r0.segments[1][i-18]);
        res.add_assign(i + len_lo, r1.segments[1][i-18]);
        res.add_assign(i + len_lo + len_lo, r2.segments[1][i-18]);
    }

    res
}

#[test]
fn test_karatsuba_mult_9() {
    let a: [Field;9] = [1,2,3,4,5,6,7,8,9]; 
    let b: [Field;9] = [1,2,3,4,5,6,7,8,9]; 
    let c_schoolbook = schoolbook_mult(a, b);
    let c_karatsuba = karatsuba_mult_9(a, b);
    
    for i in 0..18 {
        assert(c_schoolbook.get(i) == c_karatsuba.get(i));
    }
}

#[test]
fn test_karatsuba_mult_18() {
    let a: [Field;18] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18]; 
    let b: [Field;18] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18]; 
    let c_schoolbook = schoolbook_mult(a, b);
    let c_karatsuba = karatsuba_mult_18(a, b);
    
    for i in 0..36 {
        assert(c_schoolbook.get(i) == c_karatsuba.get(i));
    }
}

#[test]
fn test_karatsuba_mult_35() {
    let a: [Field;35] = [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35]; 
    let b: [Field; 35] = [
        42, 17, 93, 58, 76, 5, 31, 88, 64, 12, 
        49, 3, 21, 97, 54, 68, 29, 83, 91, 36, 
        7, 84, 65, 15, 77, 23, 56, 92, 10, 38, 
        45, 81, 20, 73, 67
    ];
    let c_schoolbook = schoolbook_mult(a, b);
    let c_karatsuba = karatsuba_mult_35(a, b);
    
    for i in 0..70 {
        assert(c_schoolbook.get(i) == c_karatsuba.get(i));
    }
}