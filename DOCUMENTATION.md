# Noir BigInt documentation

`noir-bigint` is a library that implements big-integers in Noir as a utility to develop other cryptographic primitives and tools for the Noir ecosystem. In this document, you will find all the documentation related with the implementation of the mentioned library from both theoretical and practical perspective.

## The goal

The goal is to implement a library that evaluates operations modulo an integer $p$ so that both the operands and the modulus can have arbitrary bit lengths. We will represent the operands and the modulus as $l$-bit big-integers. Each number will be defined as an array of $d$-bit *limbs*. Therefore, each value will need $N = \lceil\frac{l}{d}\rceil$ limbs for its representation.

Once the representation is defined, we want to expose an API that allows developers to write modular arithmetic zero-knowledge proofs using this big-integer modulus representation. Concretely, given $c \in \mathbb{Z}_p$, a prover wants to prove that they know $a, b \in \mathbb{Z}_p$, such that $c$ is the sum or the product of $a$ and $b$ modulo $p$. This modular arithmetic is relevant in other cryptographic constructions like RSA signature schemes.

The implementation and this documentation follow the ideas presented in the blog post "[Big integer multiplication in Noir over arbitrary moduli](https://hackmd.io/@aztec-network/S1LyK89JC)" by Zachary James Williamson. We encourage readers to read the blog post to familiarize themselves with the initial ideas. However, much of the design considered in this implementation and documentation has changed significantly compared to the ideas presented in the blog post.

In the context of ZK-proofs, choosing $d$ is an important task, given that it will affect the efficiency of the proof generation. The algorithms considered in the library require approximately $O(N^{1.5})$ multiplications and additions and $O(l)$ range checks. As we mentioned before, $d$ is inversely proportional to $N$. Hence, a large $d$ would be a good choice for a large modulus. However, if the modulus is small, it is best to choose a small $d$ to reduce the complexity of the algorithms.

In the rest of the document and the implementation, we will consider $d = 120$ as a reasonable choice of parameters. Also, in the implementation, we consider $N$ to be fixed because of the technical limitations of Noir, as the library does not support an efficient mechanism to store the limbs dynamically. Although the library support Rust-like vectors, they are not very efficient and our goal is also to implement something that can be used in production. Hence, we are limited to using fixed-length arrays to represent the collection of limbs for a number. To give more freedom during circuit development, the API is designed so that the programmer can set the value of $N$ at compile time.

## Big-integer representation

The building block to construct a big-integer library is the BigNum struct:

```rust
struct BigNum<let N: u64, Params> {
    limbs: [Field; N]
}
```

This struct represents a big-integer with $N$ limbs. Each limb will be represented as a `Field` element whose value is in the range $\lbrace 0, \dots, 2^d - 1 \rbrace$ (remember that in this case, $d = 120$). We also say that the number is represented in a radix of $d$ bits. The `Field` element typically can store more than $d$-bit numbers. Hence, we have some free bits in the most significant section of a `Field` to use in case of an overflow while operating $d$-bit elements. The amount of bits for a `Field` element depends on the backend used to run the proof. For the rest of the discussion, we will assume that the number of bits stored in a `Field` element is 254, the bit length given by the curve in the default backend. Considering this representation, if a number is represented using the vector $(a_0, \dots, a_{N-1})$, then the decimal representation of this number will be $\sum_{i=0}^{N-1} a_i \cdot 2^{d \cdot i}$.

The API is designed around this struct so the addition and multiplication are defined as methods implemented for this struct.

## Utilities

During the library's implementation, we require some utilities that allow us to implement the arithmetic operations in an idiomatic way. Here, we describe those utilities and their usage inside the main arithmetic algorithms.

### `ArrayX`

The struct `ArrayX` is an implementation of an array whose length is the product of a known multiplier `SizeMultiplier` and $N$. For example, if we define the value of $N$ at compile time and need to store twice that amount of values, we create an `ArrayX` where `SizeMultiplier` is two. This implementation is a workaround to have arrays whose length is $c \cdot N$ for a known constant $c$ because, in our implementation, the value of $N$ is considered a generic, and it is not possible to operate over generics to create an array of size $c \cdot N$.

The struct for `ArrayX` is presented next:

```rust
struct ArrayX<T, let N: u64, let SizeMultiplier: u8> {
    segments: [[T; N]; SizeMultiplier]
}
```

Notice that `ArrayX` is represented in a matrix fashion. However, it is important to remember that this can be considered an array of length `SizeMultiplier * N`.

This array implementation contains some methods of interest:
- The array implements the functions `set()` and `get()` to modify and retrieve a certain index from the array. The index of the array that is being queried needs to be between 0 and `SizeMultiplier * N - 1`.
- The implementation of the array also has some arithmetic operations like `add_assign()`, `sub_assign()`, and `mul_assign()` that allow to do the arithmetic operations in place. 

One of the main uses of `ArrayX` is to transform a number from a 120-bit radix representation to a 60-bit radix representation. When we transform over a number with $N$ limbs in the 120-bit representation, we obtain a representation in 60-bit radix with $2N$ limbs. Hence, in this case, we consider `SizeMultiplier` equal to two.

### `U60Repr`

The `U60Repr` struct represents a big integer as an array of 60-bit limbs. The main use of this struct is to convert the big integers in the 120-bit limbs into this representation to perform additions and subtraction in a lower number of bits to avoid overflow. This overflow is avoided because the sum of two 60-bit limbs is, at most, 61 bits and can be stored using the `u64` type.

The `U60Repr` struct is defined as an ArrayX of u64 elements:
```rust
struct U60Repr<let N: u32, let NumSegments: u32> {
    limbs: ArrayX<u64, N, NumSegments>
}
```

There are some methods of interest in this representation:
- `U60Repr` implements the traits `std::ops::Add` and `std::ops::Sub` which allow to the programmer to use the operators `+` and `-` between two `U60Repr`. Those traits are implemented using the schoolbook addition and subtraction in which the operation is performed limb by limb, starting from the least significant limb and storing the carry value for the next limb operation. We suggest reading "The Art of Computer Programming Volume 2" by Donal Knuth in section 4.3 for more information about how the schoolbook addition and subtraction works.
- `U60Repr` implements the trait `std::convert::From<[Field; N]>`, transforming a big-integer number with a 120-bit radix representation into a 60-bit limb representation.
- `U60Repr` implements the trait `std::convert::Into<[Field; N]>` to convert from 60-bit to 120-bit radix representation.

Using the above methods, the strategy consists of taking big integers in the 120-bit representation and converting them into a 60-bit representation. Then, we perform the additions or subtractions in this reduced representation, and we transform the resulting big integer back to the 120-bit representation to continue with the rest of the circuit. It is important to consider that most of the methods of `U60Repr` are executed using unconstrained functions to avoid the overhead that comes from using `u64` data types and comparing them.

## Modular arithmetic in ZK

First, let us remember the goal at hand. In the context of ZK-proofs, a prover wants to prove that they know $a, b \in \mathbb{Z}_p$ such that $c = a \odot b \mod p$, for some $c \in \mathbb{Z}_p$, and $\odot \in \lbrace +, \times \rbrace$. The strategy that we will consider in the implementation is to compute $q, c \in \mathbb{Z}$ such that $a \odot b = p \cdot q + c$, for $c < p$, using Noir unconstrained functions. The unconstrained functions allow us to compute intermediate witnesses that are not constrained by the proof and, therefore, cheap to compute. Once we have computed $q$ and $c$, we constrain them to the condition $a \odot b - p \cdot q - c = 0$ to prove that $c$ is the reduction modulo $p$ that we are looking for. In the implementation, we do the constraining in a more general way, considering not just the case of the addition and multiplication modulo $p$ but also an arbitrary quadratic expression. We will cover this idea in depth later.

### Constraining quadratic expressions

One of the most important parts of the algorithm is constraining to the condition $a \odot b - p \cdot q - c = 0$, for some $q, c \in \mathbb{Z}$ such that $c < p$. In the implementation, we generalize this check to more general quadratic expressions. Our goal is to constrain the following quadratic expression:

$$ \sum_{i=0}^{N_P - 1} \left(\sum_{j=0}^{N_L-1} L[i][j] \cdot \sum_{j=0}^{N_R-1} R[i][j] \right) + \sum_{i=0}^{N_A - 1} A[i] = q \cdot p $$

Here
- $N_P$ is the number of products that will be computed,
- $N_L$ is the number of products in the left hand side,
- $N_R$ is the number of products in the right hand side,
- $N_A$ is the number of linear terms in the expression,
- $L$ is a colection of terms in the left hand side,
- $R$ is a colection of terms in the right hand side, and
- $A$ is the colection of linear terms.

First, the function computes the quotient $q$ of the quadratic expression along with the borrow flags that point when an underflow occurred during the subtractions. The next section will cover the computation of the quotient and the borrow flags. Then, the function takes the left-hand side $L$ and the right-hand side $R$ and computes internal sums. Those sums are accumulated in `t0` and `t1` respectively. The same thing holds for the linear terms in $A$, accumulated in `t4`. In the construction of `t0`, `t1`, and `t4`, we subtract the negative terms, but then we add $2N$ to the current result. This correction with $2N$ is because the big-integers in our implementations are **lazily** constrained. This means that when we create a `BigNum` $a$, we do not check that $a < p$. Instead, we check that $a < 2^{\lceil \log_2 p \rceil}$. This last comparison is more efficient than the first one in the context of ZK proofs. Therefore, if we have an input $x' = x + p$ for $x \geq 0$, to compute his negative counterpart, we compute $2p - x'$ to obtain a positive number (notice that if we do $p - x'$, we obtain a negative number). At the end, $2p - x' \equiv -x' \mod p$.

After evaluating `t1`, `t2` and `t4`, we compute $t_0 * t_1 + t_4 - q \cdot c$. Here is when we use `ArrayX` to store the limbs. This is because the product of `t1` and `t2` will give us $2N - 1$ limbs. The idea behind this computation is to constrain $t_0 * t_1 + t_4 - q \cdot c = 0$. At this point, we are using schoolbook multiplication, and we are not being careful to reduce the limbs to 120 bits and considering overflows, so this product is being computed lazily. Those concerns will be covered later with the help of the borrow flags computed in the initial stage of the function.

After computing the whole expression, we need to apply the borrow to obtain the limbs in 120 bits. Here, we define the borrowed value to $2^{246}$. Notice that $246 = 120 + 120 + 6$, which is the number of bits per limb in a product of two numbers of 64 limbs. This means that our implementation is limited to products of two numbers of at most 64 limbs, which is more than enough for real-world applications.

In the last step, we must check that the condition $t_0 * t_1 + t_4 - q \cdot c = 0$. In this case, we may have a situation where the higher bits of a limb overlap with the lower bits of the next limb because of the subtractions. Therefore, we need to check that the lower 120 bits of a limb are zero and then carry the rest of the most significant bits to the next limb. This must be done from the least significant limb to the most significant one. To optimize this step, we can do the check by multiplying the limb by $2^{-120}$, and then we can constrain the result to be less than $2^{126}$ using a range proof. Notice that if there is a non-zero bit in the lower 120 bits, the multiplication with $2^{-120}$, this result will underflow, and the value will wrap around. Hence, the range check will not pass with significant probability (the probability that an underflow satisfies the range check is $2^{\text{Bits}(\mathbb{F})-126}$).

### Computation of the quotient and the borrow flags

In the computation of the quotient and the borrow flags, we will compute the quotient $q$ and the flags that tell whether the subtraction in the expression to be evaluated had an underflow. These borrow flags are used to correct the underflow by doing a carry to obtain positive limbs in the range $\lbrace 0, \dots, 2^d - 1\rbrace$.

First, the function computes the negative and positive terms in the whole expression in two data structures. The data structure for the negative numbers will store the corresponding sum of all the negative numbers with a positive sign. Notice that we are multiplying numbers of $N$ limbs; therefore, the final result that stores both the negative and positive terms in the expression has $2N - 1$ limbs.

After obtaining the terms in the final result, we normalize each limb to have 120 bits. Then, we convert them into an array of a 60-bit limb. Remember that we obtained $2N - 1$ limbs from the multiplication. Hence, transforming each 120-bit limb into a 60-bit limb results in $4N - 2$ limbs, which can be stored in an `ArrayX<N, 4>` (an array of $4N$ positions).

In the realm of 60-bit limbs, we perform the subtraction, convert it again into 120-bit limbs, and normalize them. In this way, we have computed the entire quadratic expression in a normalized format. 

Once we have the final expression, we compute $q$ using the Barrett reduction. Notice that the term $q \cdot p$ is negative in the expression. Therefore, we must include that term in the accumulator of negative terms of the complete expression.

Finally, we compute the borrow flags. For an expression of $2N - 1$ bits, there are $2N - 2$ borrow flags, given that the last limb does not have any other limb from which to borrow. The borrow flags for a position $i$ are computed as follows:
1. The positive accumulator of the limb is added with the value represented in the most significant bits located from bit 121 onwards. Notice that the 120 lowest significant bits of the limb $i - 1$ are the actual value in the 120-bit limb representation.
2. We compute a boolean to check if there is an overflow. The boolean for the limb $i$ is computed by checking if $\text{PositiveAccumulator}[i] < \text{NegativeAccumulator}[i] + BF[i-1] \cdot 2^{126}$, where $BF$ is the vector of borrow flags. The value of $2^{126}$ appears here because $2^{126} = 2^{246} - 2^{120}$ is the value that is subtracted from the current limb as borrow to the previous limb in position $i-1$. Remember that if the previous limb in position $i-1$ underflows ($BF[i-1]$), then it gets added $2^{246}$ which translates in a subtraction of $2^{246-120}$ from the limb $i$. Once the boolean is computed, it is stored in $BF[i]$.
3. We compute the value represented by the bits from position 121 onwards for the current limb $i$ as follows:
    1. Subtract the negative accumulator from the positive accumulator
    2. If the subtraction in the current limb underflows, we need to add $2^{246}$ as borrow from the next limb $i + 1$
    3. We need to subtract $2^{126} = 2^{246} - 2^{120}$ in case that the previous limb $i-1$ required a borrow from the current limb $i$.
    4. We chop the 120 least significant bits by multiplying the current value by $2^{-120}$.
We proceed with the previous steps until we reach the last limb, and then we return the quotient $q$ and the vector of borrow flags $BF$.

### Addition

Once we have a mechanism to constrain arbitrary quadratic expressions, we can do the addition as an unconstrained operation and then constrain it with `evaluate_quadratic_expression()`.

To compute the arithmetic operation $a + b = c \mod p$, we first operate the `BigNum` elements using the unconstrained functoin `__addmod()`. This method converts the 120-bit limb representation to 60-bit limb representation, adds the two vectors and reduces the value modulo $p$. Then the method converts the representation back to 120-bit limb representation, and returns the result. Given that this metod is unconstrained, we can use comparison between field elements freely, which are very expensive in a constrained context.

Once we have the addition, we need to constrain the result. This can be done using the `evaluate_quadratic_expression()` constraining to the expression $a + b - c = q \cdot p$.

### Multiplication

To do the multiplication, we first multiply two `BigNum` instances using an unconstrained function, and then we constrain the multiplication using the constrained function `evaluate_quadratic_expression()`.

For the unconstrained multiplication function, we have two different flavors for multiplying two $N$ limb numbers: We can perform a schoolbook or use the Karatsuba algorithm. Both are useful depending on the number of limbs: Karatsuba performs better for large values of $N$, while schoolbook performs better for small values of $N$.

We next describe both approaches.

#### Schoolbook multiplication

In the schoolbook approach, to multiply two $N$-limb big integers $a$ and $b$, we perform the operation `result[i + j] += a[i] * b[j]`. where $i, j \in \lbrace 0, \dots, N - 1 \rbrace$. This approach is more efficient when $N$ is small.

#### Karatsuba multiplication

Notice that the schoolbook multiplication has a $O(N^2)$ complexity. However, we can make some improvements if we use the Karatsua algorithm. For two $N$ limb elements $a$ and $b$, we can compute the product between $a$ and $b$ by dividing them into $(N/2)$-limb integers $a_l, a_h, b_l, b_h$. Then, the multiplication is done as follows:

$$ r_0 = a_l \times b_l, $$

$$ r_2 = a_h \times b_h, $$

$$ r_1 = (a_l + a_h) \times (b_l + b_h) - t_0 - t_1. $$

Then, the result will be the limbs $[r_0, r_1, r_2]$, where $t_0$ is the least significant limb. Those limbs will likely overlap, so we need an extra linear amount of additions to correct that overlap. The multiplication procedure can be applied recursively until $N=2$, and at this recursion level, we use traditional multiplication.

It is important to mention that we can do some levels of the recursion using the Karatsuba approach and finish the recursion using schoolbook multiplication. However, we need to perform a performance evaluation to determine whether it is appropriate to stop the Karatsuba recursion and finish it using schoolbooks. The evaluation is left as future work.

Due to Noir's limitations, the Karatsuba method can only be implemented for a fixed and predefined number of limbs. Therefore, we have implemented Karatsuba multiplication for the following values of $N$: 13, 17, 18, 26, and 34. The addition of more values is left for future work.
