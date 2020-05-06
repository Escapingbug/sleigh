//! Sleigh language ASTs
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use pest::{
    iterators::{Pairs, Pair},
    Parser,
};
use crate::{
    error::*,
    parser::Rule,
};

/// This is the root for internal(crate-wise) usage for easy the life of implementing semantic
/// analysis and generating InterpSetup which serves the purpose of generating AST for interpretation
/// during instruction parsing.
///
/// TL;DR : InterpSetup is the refined IR (with tables and ASTs) of RawAst.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RawRoot {
    pub(crate) defs: Vec<Definition>,
    pub(crate) cons: Vec<Constructor>,
    pub(crate) macros: Vec<PcodeMacro>,
    pub(crate) withs: Vec<WithBlock>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Endian {
    Little,
    Big,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Definition {
    Align(u64),
    Token {
        name: String,
        size: u64,
        fields: Vec<Field>
    },
    Context {
        name: String,
        fields: Vec<ContextField>,
    },
    Space {
        name: String,
        typ: SpaceType,
        size: u64,
        wordsize: u64,
        default: bool,
    },
    Varnode {
        name: String,
        offset: u64,
        size: u64,
        ids: Vec<Option<String>>,
    },
    BitRange(Vec<BitRangeDef>),
    PcodeOp(Vec<String>),
    ValueAttach {
        fields: Vec<String>,
        values: Vec<u64>,
    },
    NameAttach {
        fields: Vec<String>,
        names: Vec<String>,
    },
    VarAttach {
        fields: Vec<String>,
        regs: Vec<String>,
    },
    Endian(Endian),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Field {
    /// name of the field
    pub name: String,
    /// from which bit it starts
    pub from: u64,
    /// represents how many bits
    pub size: u64,
    /// attributes
    pub attrs: Vec<FieldAttr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum FieldAttr {
    Hex,
    Dec,
    Signed,
}

/// According to the spec, default one should be hex
impl Default for FieldAttr {
    fn default() -> Self {
        Self::Hex
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContextField {
    pub name: String,
    pub from: u64,
    pub size: u64,
    pub attrs: Vec<ContextFieldAttr>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ContextFieldAttr {
    Signed,
    NoFlow,
    Hex,
    Dec,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum SpaceType {
    RamSpace,
    RomSpace,
    RegSpace,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BitRangeDef {
    pub name: String,
    pub reg: String,
    pub from: u64,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PcodeMacro {
    pub name: String,
    pub args: Vec<String>,
    pub sem_body: Vec<Statement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Statement {
    Label(String),
    Section(String),
    Assignment {
        local: bool,
        from: LValue,
        to: Expr,
    },
    Declaration(String, Option<u64>),
    Funcall {
        func: String,
        args: Vec<String>,
    },
    Build(String),
    CrossBuild(Expr, String),
    Goto(JumpDest),
    If(Expr, JumpDest),
    Call(JumpDest),
    Export(Expr),
    Return(Expr),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum JumpDest {
    Id(String),
    Expr(Expr),
    Int(u64),
    IntWithSpace(u64, String),
    Label(String),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum LValue {
    SemBitRange {
        name: String,
        from: u64,
        size: u64
    },
    IdBit(String, u64),
    Id(String),
    /// *expr = ?;
    Addr(Expr),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Expr {
    // bool or
    BoolOr(Box<Expr>, Box<Expr>),

    // bool and
    BoolAnd(Box<Expr>, Box<Expr>),
    BoolXor(Box<Expr>, Box<Expr>),

    // or
    Or(Box<Expr>, Box<Expr>),
    // xor
    Xor(Box<Expr>, Box<Expr>),
    // and
    And(Box<Expr>, Box<Expr>),

    // eq
    Equal(Box<Expr>, Box<Expr>),
    NotEqual(Box<Expr>, Box<Expr>),
    FloatEqual(Box<Expr>, Box<Expr>),
    FloatNotEqual(Box<Expr>, Box<Expr>),

    // compare
    Less(Box<Expr>, Box<Expr>),
    GreqtEqual(Box<Expr>, Box<Expr>),
    LessEqual(Box<Expr>, Box<Expr>),
    Great(Box<Expr>, Box<Expr>),
    SignedLess(Box<Expr>, Box<Expr>),
    SignedGreatEqual(Box<Expr>, Box<Expr>),
    SignedLessEqual(Box<Expr>, Box<Expr>),
    SignedGreat(Box<Expr>, Box<Expr>),
    FloatLess(Box<Expr>, Box<Expr>),
    FloatGreatEqual(Box<Expr>, Box<Expr>),
    FloatLessEqual(Box<Expr>, Box<Expr>),
    FloatGreat(Box<Expr>, Box<Expr>),

    // shift
    LeftShift(Box<Expr>, Box<Expr>),
    RightShift(Box<Expr>, Box<Expr>),
    SignedRightShift(Box<Expr>, Box<Expr>),

    // add
    Plus(Box<Expr>, Box<Expr>),
    Minus(Box<Expr>, Box<Expr>),
    FloatPlus(Box<Expr>, Box<Expr>),
    FloatMinus(Box<Expr>, Box<Expr>),

    // mult
    Mult(Box<Expr>, Box<Expr>),
    Div(Box<Expr>, Box<Expr>),
    Rem(Box<Expr>, Box<Expr>),
    SignedDiv(Box<Expr>, Box<Expr>),
    SignedRem(Box<Expr>, Box<Expr>),
    FloatMult(Box<Expr>, Box<Expr>),
    FloatDiv(Box<Expr>, Box<Expr>),

    // unary
    BoolNot(Box<Expr>),
    Not(Box<Expr>),
    UnaryMinus(Box<Expr>),
    FloatUnaryMinus(Box<Expr>),
    /// *expr
    SizedStar {
        space: String,
        size: u64,
        expr: Box<Expr>
    },

    // apply
    Apply(String, Vec<Box<Expr>>),

    // term
    Term(ExprTerm)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ExprTerm {
    SemBitRange {
        name: String,
        from: u64,
        size: u64
    },
    Varnode(VarnodeTerm)
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum VarnodeTerm {
    Id(String),
    IdSized(String, u64),
    AddrOf {
        target: Box<VarnodeTerm>,
        size: u64,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct WithBlock {
    pub(crate) id: Option<String>,
    pub(crate) bitpat: Option<PEquation>,
    pub(crate) ctx_block: Vec<ContextStmt>,
    pub(crate) root: RawRoot,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PEquation {
    Or(Box<PEquation>, Box<PEquation>),
    Seq(Box<PEquation>, Box<PEquation>),
    And(Box<PEquation>, Box<PEquation>),
    EllipsisRight(Box<PEquation>),
    EllipsisLeft(Box<PEquation>),
    Constraint(Constraint),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum Constraint {
    Id(String),
    Equal(String, Box<PExpr>),
    NotEqual(String, Box<PExpr>),
    Less(String, Box<PExpr>),
    Great(String, Box<PExpr>),
    GreatEqual(String, Box<PExpr>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PExpr {
    Or(Box<PExpr>, Box<PExpr>),
    Xor(Box<PExpr>, Box<PExpr>),
    And(Box<PExpr>, Box<PExpr>),
    LeftShift(Box<PExpr>, Box<PExpr>),
    RightShift(Box<PExpr>, Box<PExpr>),
    Plus(Box<PExpr>, Box<PExpr>),
    Minus(Box<PExpr>, Box<PExpr>),
    Mult(Box<PExpr>, Box<PExpr>),
    Div(Box<PExpr>, Box<PExpr>),
    UnaryMinus(Box<PExpr>),
    Not(Box<PExpr>),
    Apply(String, Vec<Box<PExpr>>),
    Term(PExprTerm),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum PExprTerm {
    Id(String),
    Int(u64),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ContextStmt {
    Assign(String, Box<PExpr>),
    Funcall(Box<PExpr>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Constructor {
    pub tab: String,
    /// display format string
    pub display: String,
    pub bitpat: PEquation,
    pub ctx_block: Vec<ContextStmt>,
    pub sem_body: Vec<Statement>,
}

impl RawRoot {

    fn find_endian_from_pair(pair: Pair<Rule>) -> Result<Endian> {
        for span in pair.into_inner() {
            if span.as_rule() == Rule::endian {
                match span.into_inner().next().unwrap().as_rule() {
                    Rule::KEY_LITTLE => return Ok(Endian::Little),
                    Rule::KEY_BIG => return Ok(Endian::Big),
                    _ => {}
                }
            }
        }

        Err(Error::EndianNotFound)
    }

    fn handle_aligndef(pair: Pair<Rule>) -> Result<Definition> {
        // jump over "define alignment="
        let mut pairs = pair.into_inner();
        pairs.next().unwrap(); // "define"
        pairs.next().unwrap(); // "alignment"
        pairs.next().unwrap(); // "="
        let align = pairs
            .next()
            .unwrap(); // integer
        Ok(Definition::Align(align.as_str().parse().unwrap()))
    }

    fn handle_def(pair: Pair<Rule>) -> Result<Definition> {
        match pair.as_rule() {
            Rule::aligndef => {
                Self::handle_aligndef(pair)
            },
            _ => unimplemented!()
        }
    }

    pub(crate) fn from_parsed(mut spec: Pairs<Rule>) -> Result<Self> {
        //let mut defs = Vec::new();
        let spec = &mut spec.next()
            .ok_or(Error::EmptySpec)?
            .into_inner();
        let endian = Self::find_endian_from_pair(spec.next().ok_or(Error::EndianNotFound)?)?;
        let mut defs = Vec::new();
        for span in spec {
            match span.as_rule() {
                Rule::definition => {
                    defs.push(Self::handle_def(span.into_inner().next().unwrap())?);
                },
                _ => {
                    unimplemented!("rule not yet implemented")
                }
            }
        }
        unimplemented!()
    }
}

#[test]
fn test_raw_construct() {
    use std::io::Read;
    use std::fs::File;
    use crate::parser::{SleighParser, Rule};

    let mut spec = File::open("test/test.spec").unwrap();
    let mut s = String::new();
    spec.read_to_string(&mut s).unwrap();
    let spec = SleighParser::parse(Rule::spec, &s).unwrap();

    RawRoot::from_parsed(spec).unwrap();
}
