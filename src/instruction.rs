use serde_derive::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddrSpace {
    pub id: usize,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Varnode {
    pub addr: usize,
    pub num: usize,
    pub addr_space: AddrSpace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PcodeIns {
    /// v0:2; v0(2); least significant n bytes of v0
    Subpiece(Varnode, usize),
    /// originally "(simulated)", v0[6,1] extract range of bits
    Extract(Varnode, usize),
    /// * v1; *[spc]v1; *:2 v1; *[spc]:2 v1; dereference
    Load(Varnode),
    /// !v0
    BoolNegate(Varnode),
    /// ~v0, bitwise
    IntNegate(Varnode),
    /// twos complement of v0
    Int2Comp(Varnode),
    /// f- v0, floating-point inverse
    FloatNeg(Varnode),
    /// v0 * v1
    IntMult(Varnode, Varnode),
    /// v0 / v1, unsigned
    IntDiv(Varnode, Varnode),
    /// v0 s/ v1, signed
    IntSDiv(Varnode, Varnode),
    /// v0 % v1, unsigned
    IntRem(Varnode, Varnode),
    /// v0 s% v1, signed
    IntSRem(Varnode, Varnode),
    /// v0 f/ v1
    FloatDiv(Varnode, Varnode),
    /// v0 f* v1
    FloatMult(Varnode, Varnode),
    /// v0 + v1
    IntAdd(Varnode, Varnode),
    /// v0 - v1
    IntSub(Varnode, Varnode),
    /// v0 f+ v1
    FloatAdd(Varnode, Varnode),
    /// v0 f- v1
    FloatSub(Varnode, Varnode),
    /// v0 << v1, unsigned, logic
    IntLeft(Varnode, Varnode),
    /// v0 >> v1, unsigned, logic
    IntRight(Varnode, Varnode),
    /// v0 s>> v1, signed, arithmetic
    IntSRight(Varnode, Varnode),
    /// v0 s< v1, v0 s> v0, signed
    IntSLess(Varnode, Varnode),
    /// v0 s<= v1, v1 s>= v0, signed
    IntSLessEqual(Varnode, Varnode),
    /// v0 < v1, v1 > v0, unsigned
    IntLess(Varnode, Varnode),
    /// v0 <= v1, v1 >= v0, unsigned
    IntLessEqual(Varnode, Varnode),
    /// v0 f< v1, v1 f> v0
    FloatLess(Varnode, Varnode),
    /// v0 f<= v1, v1 f>= v0
    FloatLessEqual(Varnode, Varnode),
    /// v0 == v1
    IntEqual(Varnode, Varnode),
    /// v0 != v1
    IntNotEqual(Varnode, Varnode),
    /// v0 f== v1
    FloatEqual(Varnode, Varnode),
    /// v0 f!= v1
    FloatNotEqual(Varnode, Varnode),
    /// v0 & v1
    IntAnd(Varnode, Varnode),
    /// v0 ^ v1
    IntXor(Varnode, Varnode),
    /// v0 | v1
    IntOr(Varnode, Varnode),
    /// v0 ^^ v1
    BoolXor(Varnode, Varnode),
    /// v0 && v1
    BoolAnd(Varnode, Varnode),
    /// v0 || v1
    BoolOr(Varnode, Varnode),
    /// zext(v0), zero extension
    IntZext(Varnode),
    /// sext(v0), signed extension
    IntSext(Varnode),
    /// carry(v0, v1), true if adding would produce an unsigned carry
    IntCarry(Varnode, Varnode),
    /// scarry(v0, v1), true if adding would produce an signed carry
    IntSCarry(Varnode, Varnode),
    /// sborrow(v0, v1), true if subtracting would produce a signed borrow
    IntSBorrow(Varnode, Varnode),
    /// nan(v0) true if is an NaN
    FloatNan(Varnode),
    /// abs(v0) abs value as float
    FloatAbs(Varnode),
    /// sqrt(v0)
    FloatSqrt(Varnode),
    /// int2float(v0)
    Int2Float(Varnode),
    /// float2float(v0)
    Float2Float(Varnode),
    /// trunc(v0) signed integer obtained by truncatin v0
    Trunc(Varnode),
    /// ceil(v0)
    FloatCeil(Varnode),
    /// floor(v0)
    FloatFloor(Varnode),
    /// round(v0)
    FloatRound(Varnode),
    /// cpool(v0, ...) access value from the constant pool
    CpoolRef(Varnode, Vec<Varnode>),
    /// allocate object of type described by v0
    /// (originally NEW, but to avoid common pattern, changed to NewObj)
    NewObj(Varnode),
    /// v0 = v1; assignment of v1 to v0
    Copy(Varnode, Varnode),
    /// *v0 = v1; *[spc]v0 = v1; *:4 v0 = v1; *[spc]:4 v0 = v1;
    Store(Varnode, Varnode),
    // ident(v0, ...); user defined operation
    // do not support user defined for now: UserDefined(String, Vec<Varnode>),
    /// goto v0;
    Branch(Varnode),
    /// if (v0) goto v1;
    CBranch(Varnode),
    /// goto [v0];
    BranchInd(Varnode),
    /// call v0;
    Call(Varnode),
    /// call [v0];
    CallInd(Varnode),
    /// return [v0]; branch execution to v0 viewed as an offset in current space.
    /// hinted to be subroutine return
    Return(Varnode),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Instruction {
    pcode: Vec<PcodeIns>,
    display: String,
}
