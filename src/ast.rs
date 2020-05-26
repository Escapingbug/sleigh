//! Sleigh language ASTs
use std::{
    collections::HashMap,
    str::FromStr,
};
use serde::{Deserialize, Serialize};
use pest::{
    iterators::{Pairs, Pair},
    Parser,
};
use crate::{
    error::*,
    parser::Rule,
};
use snailquote::unescape;

macro_rules! skip {
    ($item: ident) => {
        $item.next().unwrap();
    }
}

macro_rules! next_str {
    ($item: ident) => {
        $item.next().unwrap().as_str().to_string()
    }
}

macro_rules! next_int {
    ($item: ident) => {
        parse_int::parse($item.next().unwrap().as_str())?
    }
}

macro_rules! expr_layer_impl {
    ($func_name: ident, $next_func: ident, $expr_cons: path) => {
        fn $func_name(expr: Pair<Rule>) -> Result<Expr> {
            let mut pairs = expr.into_inner();
            let mut lhs = Self::$next_func(pairs.next().unwrap())?;
            loop {
                if let Some(_) = pairs.next() {
                    let rhs = Box::new(Self::$next_func(pairs.next().unwrap())?);
                    lhs = $expr_cons(Box::new(lhs), rhs); 
                } else {
                    break;
                }
            }

            Ok(lhs)
        }
    };
}

macro_rules! make_op_impl_arm {
    ($lhs: ident, $rhs: ident)
        macro_rules! op_impl {
            ($rule: ident, $cons: ident) => {
                Rule::$rule => Expr::$cons(Box::new($lhs), Box::new($rhs)),
            }
        };
}

// TODO Current integer cannot be more than 64-bit. Original ghidra's implementation has occupied
// BigInteger, so it might allow arbitrary size. Also, some processor may have 128 bit constants,
// so this is useful. It should be fixed after prototype, and we need a better strategy to switch
// between arbitrary size integer and fixed size integer.

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
        spacename: String,
        offset: u64,
        size: u64,
        names: Vec<Option<String>>,
    },
    BitRange(Vec<BitRangeDef>),
    PcodeOp(String),
    ValueAttach {
        fields: Vec<String>,
        values: Vec<Option<i64>>,
    },
    NameAttach {
        fields: Vec<String>,
        names: Vec<Option<String>>,
    },
    VarAttach {
        fields: Vec<String>,
        regs: Vec<Option<String>>,
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

impl FromStr for SpaceType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "ram_space" => Ok(Self::RamSpace),
            "rom_space" => Ok(Self::RomSpace),
            "register_space" => Ok(Self::RegSpace),
            s => Err(Error::UnknownSpace {
                space: s.to_string()
            })
        }
    }
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

    fn handle_endian(pair: Pair<Rule>) -> Result<Definition> {
        for span in pair.into_inner() {
            if span.as_rule() == Rule::endian {
                match span.into_inner().next().unwrap().as_rule() {
                    Rule::KEY_LITTLE => return Ok(Definition::Endian(Endian::Little)),
                    Rule::KEY_BIG => return Ok(Definition::Endian(Endian::Big)),
                    _ => {}
                }
            }
        }

        Err(Error::EndianNotFound)
    }

    fn handle_aligndef(aligndef: Pair<Rule>) -> Result<Definition> {
        let mut pairs = aligndef.into_inner();
        // jump over "define alignment="
        skip!(pairs); // "define"
        skip!(pairs); // "alignment"
        skip!(pairs); // "="
        let align = pairs
            .next()
            .unwrap(); // integer
        Ok(Definition::Align(align.as_str().parse()?))
    }

    fn handle_field_attr(fieldmod: Pair<Rule>) -> Result<FieldAttr> {
        let attr = fieldmod.into_inner().next().unwrap();
        let res = match attr.as_rule() {
            Rule::KEY_SIGNED => FieldAttr::Signed,
            Rule::KEY_DEC => FieldAttr::Dec,
            Rule::KEY_HEX => FieldAttr::Hex,
            _ => unreachable!(),
        };
        Ok(res)
    }

    fn handle_field_attrs(fieldmods: Pair<Rule>) -> Result<Vec<FieldAttr>> {
        let mut attrs = vec![];
        for fieldmod in fieldmods.into_inner() {
            attrs.push(Self::handle_field_attr(fieldmod)?);
        }

        Ok(attrs)
    }

    fn handle_fielddef(fielddef: Pair<Rule>) -> Result<Field> {
        // "ID = (X,Y) mods"
        let mut pairs = fielddef.into_inner();
        let id = next_str!(pairs);
        // jump over "=(" (which looks like a face)
        skip!(pairs); // "="
        skip!(pairs); // "("
        let from = next_int!(pairs);
        skip!(pairs); // ","
        let size = next_int!(pairs);
        skip!(pairs); // ")"
        let attrs = Self::handle_field_attrs(pairs.next().unwrap())?;

        Ok(Field {
            name: id,
            from: from,
            size: size,
            attrs: attrs
        })
    }

    fn handle_fielddefs(fielddefs: Pair<Rule>) -> Result<Vec<Field>> {
        let mut fields = vec![];
        for span in fielddefs.into_inner() {
            fields.push(Self::handle_fielddef(span)?);
        }
        Ok(fields)
    }

    fn handle_tokendef(tokendef: Pair<Rule>) -> Result<Definition> {
        let mut pairs = tokendef.into_inner();
        // "define token ID (N) FIELDS;"

        // jump over "define token"
        skip!(pairs); // "define"
        skip!(pairs); // "token"

        let id = next_str!(pairs);;

        skip!(pairs); // "("
        let size = next_int!(pairs);
        skip!(pairs); // ")"

        let fields = Self::handle_fielddefs(pairs.next().unwrap())?;
        Ok(Definition::Token {
            name: id,
            size: size,
            fields: fields
        })
    }

    fn handle_context_attr(field_mod: Pair<Rule>) -> Result<ContextFieldAttr> {
        let field_mod = field_mod.into_inner().next().unwrap();
        let res = match field_mod.as_rule() {
            Rule::KEY_SIGNED => ContextFieldAttr::Signed,
            Rule::KEY_NOFLOW => ContextFieldAttr::NoFlow,
            Rule::KEY_HEX => ContextFieldAttr::Hex,
            Rule::KEY_DEC => ContextFieldAttr::Dec,
            _ => unreachable!()
        };
        Ok(res)
    }

    fn handle_context_attrs(field_mods: Pair<Rule>) -> Result<Vec<ContextFieldAttr>> {
        let mut attrs = vec![];
        for field_mod in field_mods.into_inner() {
            attrs.push(Self::handle_context_attr(field_mod)?);
        }
        Ok(attrs)
    }

    fn handle_context_field(field: Pair<Rule>) -> Result<ContextField> {
        // "ID=(X,Y) mods"
        let mut pairs = field.into_inner();
        let id = next_str!(pairs);
        skip!(pairs); // "="
        skip!(pairs); // "("
        let from = next_int!(pairs);
        skip!(pairs); // ","
        let size = next_int!(pairs);
        skip!(pairs); // ")"
        let attrs = Self::handle_context_attrs(pairs.next().unwrap())?;
        Ok(ContextField {
            name: id,
            from: from,
            size: size,
            attrs: attrs
        })
    }

    fn handle_context_fields(contextfields: Pair<Rule>) -> Result<Vec<ContextField>> {
        let mut fields = vec![];
        for field in contextfields.into_inner() {
            fields.push(Self::handle_context_field(field)?);
        }
        Ok(fields)
    }

    fn handle_contextdef(contextdef: Pair<Rule>) -> Result<Definition> {
        // "define context ID contextfielddefs"
        let mut pairs = contextdef.into_inner();
        skip!(pairs); // "define"
        skip!(pairs); // "context"
        let id = next_str!(pairs);
        let fields = Self::handle_context_fields(pairs.next().unwrap())?;
        Ok(Definition::Context {
            name: id,
            fields: fields 
        })
    }

    fn handle_spacedef(spacedef: Pair<Rule>) -> Result<Definition> {
        // "define space ID mods"
        let mut pairs = spacedef.into_inner();
        skip!(pairs); // "define"
        skip!(pairs); // "space"
        let id = next_str!(pairs);

        // default values
        let mut size = 4;
        let mut typ = SpaceType::RamSpace;
        let mut wordsize = 1;
        let mut default = false;

        // mods
        let spacemods = pairs.next().unwrap();
        for spacemod in spacemods.into_inner() {
            match spacemod.as_rule() {
                Rule::KEY_DEFAULT => { default = true; },
                Rule::typemod => {
                    // type=TYPE
                    let mut pairs = spacemod.into_inner();
                    skip!(pairs); // "type"
                    skip!(pairs); // "="
                    typ = SpaceType::from_str(pairs.next().unwrap().as_str())?;
                },
                Rule::sizemod => {
                    // size=X
                    let mut pairs = spacemod.into_inner();
                    skip!(pairs); // "size"
                    skip!(pairs); // "="
                    size = next_int!(pairs);
                },
                Rule::wordsizemod => {
                    // wordsize=X
                    let mut pairs = spacemod.into_inner();
                    skip!(pairs); // "wordsize"
                    skip!(pairs); // "="
                    wordsize = next_int!(pairs);
                },
                _ => unreachable!()
            }
        }

        Ok(Definition::Space {
            name: id,
            typ: typ,
            size: size,
            wordsize: wordsize,
            default: default
        })
    }

    fn handle_id_list(id_list: Pair<Rule>) -> Result<Vec<Option<String>>> {
        let pairs = id_list.into_inner();
        let mut names = vec![];
        for pair in pairs {
            match pair.as_rule() {
                Rule::LBRACKET | Rule::RBRACKET => continue,
                Rule::identifier => {
                    names.push(Some(pair.as_str().to_string()));
                },
                Rule::wildcard => {
                    names.push(None);
                },
                _ => unreachable!()
            }
        }
        Ok(names)
    }

    fn handle_varnodedef(varnodedef: Pair<Rule>) -> Result<Definition> {
        // "define SPACENAME offset=X size=Y names"
        let mut pairs = varnodedef.into_inner();
        skip!(pairs); // "define"
        let spacename = next_str!(pairs);
        skip!(pairs); // "offset"
        skip!(pairs); // "="
        let offset = next_int!(pairs);
        skip!(pairs); // "size"
        skip!(pairs); // "="
        let size = next_int!(pairs);
        let names = Self::handle_id_list(pairs.next().unwrap())?;
        Ok(Definition::Varnode {
            spacename: spacename,
            offset: offset,
            size: size,
            names: names
        })
    }

    fn handle_bitranges(bitranges: Pair<Rule>) -> Result<Vec<BitRangeDef>> {
        let bitranges = bitranges.into_inner().next().unwrap();
        let mut bitrangedefs = vec![];
        for bitrange in bitranges.into_inner() {
            // ID=REG[X,Y]
            let mut pairs = bitrange.into_inner();
            let name = next_str!(pairs);
            skip!(pairs); // "="
            let reg = next_str!(pairs);
            skip!(pairs); // "["
            let from = next_int!(pairs);
            skip!(pairs); // ","
            let size = next_int!(pairs);

            bitrangedefs.push(BitRangeDef {
                name: name,
                reg: reg,
                from: from,
                size: size
            });
        }
        Ok(bitrangedefs)
    }

    fn handle_bitrangedef(def: Pair<Rule>) -> Result<Definition> {
        // "define bitrange bitranges"
        let mut pairs = def.into_inner();
        skip!(pairs); // "define"
        skip!(pairs); // "bitrange"
        let bitranges = Self::handle_bitranges(pairs.next().unwrap())?;
        Ok(Definition::BitRange(bitranges))
    }

    fn handle_pcodeopdef(def: Pair<Rule>) -> Result<Definition> {
        // "define pcodeop id_list"
        let mut pairs = def.into_inner();
        skip!(pairs); // "define"
        skip!(pairs); // "pcodeop"
        let id = next_str!(pairs);
        Ok(Definition::PcodeOp(id))
    }

    fn handle_intblist(intblist: Pair<Rule>) -> Result<Vec<Option<i64>>> {
        let mut intlist = vec![];

        for pair in intblist.into_inner() {
            match pair.as_rule() {
                Rule::LBRACKET | Rule::RBRACKET => continue,
                Rule::neginteger => {
                    let mut pairs = pair.into_inner();
                    let next = pairs.next().unwrap();
                    let val = match next.as_rule() {
                        Rule::integer => next.as_str().parse()?,
                        Rule::MINUS => {
                            let val: i64 = next_int!(pairs);
                            -val
                        },
                        _ => unreachable!()
                    };
                    intlist.push(Some(val));
                },
                Rule::UNDERSCORE => intlist.push(None),
                _ => unreachable!(),
            }
        }

        Ok(intlist)
    }

    fn handle_fieldlist(pairs: Pair<Rule>) -> Result<Vec<String>> {
        let mut fieldlist = vec![];
        for pair in pairs.into_inner() {
            match pair.as_rule() {
                Rule::LBRACKET | Rule::RBRACKET => continue,
                Rule::identifier => fieldlist.push(pair.as_str().to_string()),
                _ => unreachable!()
            }
        }
        Ok(fieldlist)
    }

    fn handle_valueattach(def: Pair<Rule>) -> Result<Definition> {
        // "attach values idlist intblist"
        let mut pairs = def.into_inner();
        skip!(pairs); // "attach"
        skip!(pairs); // "values"
        let fields = Self::handle_fieldlist(pairs.next().unwrap())?;
        let values = Self::handle_intblist(pairs.next().unwrap())?;
        Ok(Definition::ValueAttach {
            fields: fields,
            values: values
        })
    }

    fn handle_nameattach(def: Pair<Rule>) -> Result<Definition> {
        // "attach names id_list stringoridentlist"
        let mut pairs = def.into_inner();
        skip!(pairs); // "attach"
        skip!(pairs); // "names"
        let fields = Self::handle_fieldlist(pairs.next().unwrap())?;
        let mut id_list = vec![];
        for string_or_id in pairs.next().unwrap().into_inner() {
            match string_or_id.as_rule() {
                Rule::LBRACKET | Rule::RBRACKET => continue,
                Rule::identifier => {
                    id_list.push(Some(string_or_id.as_str().to_string()));
                },
                Rule::wildcard => {
                    id_list.push(None);
                },
                Rule::qstring => {
                    id_list.push(Some(unescape(string_or_id.as_str())?))
                },
                _ => unreachable!()
            }
        }

        Ok(Definition::NameAttach {
            fields: fields,
            names: id_list
        })
    }

    fn handle_varattach(def: Pair<Rule>) -> Result<Definition> {
        // attach variables id_list id_list
        let mut pairs = def.into_inner();
        skip!(pairs); // "attach"
        skip!(pairs); // "variables"
        let fields = Self::handle_fieldlist(pairs.next().unwrap())?;
        let regs = Self::handle_id_list(pairs.next().unwrap())?;
        Ok(Definition::VarAttach {
            fields: fields,
            regs: regs
        })
    }

    fn handle_def(def: Pair<Rule>) -> Result<Definition> {
        let def = def.into_inner().next().unwrap();
        match def.as_rule() {
            Rule::aligndef => {
                Self::handle_aligndef(def)
            },
            Rule::tokendef => {
                Self::handle_tokendef(def)
            },
            Rule::contextdef => {
                Self::handle_contextdef(def)
            },
            Rule::spacedef => {
                Self::handle_spacedef(def)
            },
            Rule::varnodedef => {
                Self::handle_varnodedef(def)
            },
            Rule::bitrangedef => {
                Self::handle_bitrangedef(def)
            },
            Rule::pcodeopdef => {
                Self::handle_pcodeopdef(def)
            },
            Rule::valueattach => {
                Self::handle_valueattach(def)
            },
            Rule::nameattach => {
                Self::handle_nameattach(def)
            },
            Rule::varattach => {
                Self::handle_varattach(def)
            },
            _ => unreachable!()
        }
    }

    fn handle_arguments(arguments: Pair<Rule>) -> Result<Vec<String>> {
        let mut args = vec![];
        if arguments.as_str().len() == 0 {
            return Ok(args);
        }

        let oplist = arguments.into_inner().next().unwrap().into_inner();

        for op in oplist {
            match op.as_rule() {
                Rule::identifier => args.push(op.as_str().to_string()),
                Rule::COMMA => continue,
                _ => unreachable!(),
            }
        }

        Ok(args)
    }

    fn handle_lvalue(lvalue: Pair<Rule>) -> Result<LValue> {
        unimplemented!("lvalue")
    }

    fn handle_sizedstar(rule: Pair<Rule>) -> Result<(String, u64)> {
        let mut pairs = rule.into_inner();
        skip!(pairs); // "*"
        let mut next = pairs.next();
        if next == None {
            // default case, use 0 to denote default size
            return Ok(("default".to_string(), 0));
        }

        let next = next.unwrap();
        match next.as_rule() {
            Rule::COLON => {
                // *:N
                let size = next_int!(pairs);
                return Ok(("default".to_string(), size));
            },
            Rule::LBRACKET => {
                let id = next_str!(pairs);
                skip!(pairs); // "]"
                let next = pairs.next().unwrap(); // ":"
                if next == None {
                    return Ok((id, 0));
                }

                let size = next_int!(pairs);
                return Ok((id, size));
            },
            _ => unreachable!()
        }

        unreachable!()
    }

    fn handle_expr_operands(ops: Pair<Rule>) -> Result<Vec<Box<Expr>>> {
        let mut pairs = ops.into_inner();
        skip!(pairs); // "("
        let next = pairs.next().unwrap();
        if next.as_rule() == Rule::RPAREN {
            return Ok(Vec::new());
        }

        let mut args = Vec::new();
        args.push(Box::new(Self::handle_expr(next)?));

        loop {
            let next = pairs.next();
            match next.as_rule() {
                Rule::COMMA => continue,
                Rule::RPAREN => break,
                _ => args.push(Box::new(Self::handle_expr(next)?)),
            }
        }

        Ok(args)
    }

    fn handle_expr_apply(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let func_name = next_str!(pairs);
        let operands = Self::handle_expr_operands(pairs)?;
        Ok(Expr::Apply(func_name, operands))
    }

    fn handle_sembitrange(sembitrange: Pair<Rule>) -> Result<Expr> {
        unimplemented!("handle_sembitrange")
    }

    fn handle_varnode(varnode: Pair<Rule>) -> Result<VarnodeTerm> {
        unimplemented!("handle_varnode")
    }

    fn handle_expr_term(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let next = pairs.next();
        match next.as_rule() {
            Rule::LPAREN => Self::handle_expr(pairs.next().unwrap()),
            Rule::sembitrange => {
                let (name, from, size) = Self::handle_sembitrange(next);
                Ok(ExprTerm::SemBitRange {
                    name: name,
                    from: from,
                    size: size
                })
            },
            Rule::varnode => {
                let varnode_term = Self::handle_varnode(next);
                Ok(ExprTerm::Varnode(varnode_term))
            },
            _ => unreachable!()
        }
    }

    fn handle_expr_func(expr: Pair<Rule>) -> Result<Expr> {
        let mut inner = expr.into_inner().next().unwrap();
        match inner.as_rule() {
            Rule::expr_apply => {
                Self::handle_expr_apply(inner)
            },
            Rule::expr_term => {
                Self::handle_expr_term(inner)
            },
            _ => unreachable!(),
        }
    }

    fn handle_expr_unary(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let mut next = pairs.next().unwrap();
        match next.as_rule() {
            Rule::EXCLAIM => {
                Ok(Expr::BoolNot(Self::handle_expr_func(pairs.next().unwrap()))?)
            },
            Rule::TILDE => {
                Ok(Expr::Not(Self::handle_expr_func(pairs.next().unwrap()))?)
            },
            Rule::MINUS => {
                Ok(Expr::UnaryMinus(Self::handle_expr_func(pairs.next().unwrap()))?)
            },
            Rule::FMINUS => {
                Ok(Expr::FloatUnaryMinus(Self::handle_expr_func(pairs.next().unwrap()))?)
            },
            Rule::sizedstar => {
                let (space, size) = Self::handle_sizedstar(next)?;
                Ok(Expr::SizedStar {
                    space: space,
                    size, size,
                    expr: Self::handle_expr_func(pairs.next().unwrap())?
                })
            },
            Rule::expr_func => {
                Self::handle_expr_func(pairs.next().unwrap())
            }
        }
    }

    fn handle_expr_mult(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let mut lhs = Self::handle_expr_unary(pairs.next().unwrap())?;
        loop {
            if let Some(op) = pairs.next() {
                let rhs = Self::handle_expr_unary(pairs.next().unwrap())?;
                make_op_impl_arm!(lhs, rhs);
                lhs = match op {
                    op_impl!(ASTERISK, Mult),
                    op_impl!(SLASH, Div),
                    op_impl!(PERCENT, Rem),
                    op_impl!(SDIV, SignedDiv),
                    op_impl!(SREM, SignedRem),
                    op_impl!(FMULT, FloatMult),
                    op_impl!(FDIV, FloatDiv),
                    _ => unreachable!()
                };
            } else {
                break;
            }
        }

        Ok(lhs)
    }

    fn handle_expr_add(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let mut lhs = Self::handle_expr_mult(pairs.next().unwrap())?;
        loop {
            if let Some(op) = pairs.next() {
                let rhs = Self::handle_expr_mult(pairs.next().unwrap())?;
                make_op_impl_arm!(lhs, rhs);
                lhs = match op {
                    op_impl!(PLUS, Plus),
                    op_impl!(MINUS, Minus),
                    op_impl!(FPLUS, FloatPlus),
                    op_impl!(FMINUS, FloatMinus),
                    _ => unreachable!()
                };
            } else {
                break;
            }
        }

        Ok(lhs)
    }

    fn handle_expr_shift(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let mut lhs = Self::handle_expr_add(pairs.next().unwrap())?;
        loop {
            if let Some(op) = pairs.next() {
                let rhs = Self::handle_expr_add(pairs.next().unwrap())?;
                make_op_impl_arm!(lhs, rhs);
                lhs = match op {
                    op_impl!(LEFT, LeftShift),
                    op_impl!(RIGHT, RightShift),
                    op_impl!(SRIGHT, SignedRightShift),
                    _ => unreachable!()
                }
            } else {
                break;
            }
        }

        Ok(lhs)
    }

    fn handle_expr_comp(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let mut lhs = Self::handle_expr_shift(pairs.next().unwrap())?;
        loop {
            if let Some(op) = pairs.next() {
                let rhs = Self::handle_expr_shift(pairs.next().unwrap())?;
                make_op_impl_arm!(lhs, rhs);
                lhs = match op {
                    op_impl!(LESS, Less),
                    op_impl!(GREATEQUAL, GreatEqual),
                    op_impl!(LESSEQUAL, LessEqual),
                    op_impl!(GREAT, Great),
                    op_impl!(SLESS, SignedLess),
                    op_impl!(SGREATEQUAL, SignedGreatEqual),
                    op_impl!(SLESSEQUAL, SignedLessEqual),
                    op_impl!(SGREAT, SignedGreat),
                    op_impl!(FLESS, FloatLess),
                    op_impl!(FGREATEQUAL, FloatGreatEqual),
                    op_impl!(FLESSEQUAL, FloatLessEqual),
                    op_impl!(FGREAT, FloatGreat),
                    _ => unreachable!()
                };
            } else {
                break;
            }
        }

        Ok(lhs);
    }

    fn handle_expr_eq(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let mut lhs = Self::handle_expr_comp(pairs.next().unwrap())?;
        loop {
            if let Some(op) = pairs.next() {
                let rhs = Self::handle_expr_comp(pairs.next().unwrap())?;
                lhs = match op {
                    Rule::EQUAL => Expr::Equal(Box::new(lhs), Box::new(rhs)),
                    Rule::NOTEQUAL => Expr::NotEqual(Box::new(lhs), Box::new(rhs)),
                    Rule::FEQUAL => Expr::FloatEqual(Box::new(lhs), Box::new(rhs)),
                    Rule::FNOTEQUAL => Expr::FloatNotEqual(Box::new(lhs), Box::new(rhs)),
                    _ => unreachable!()
                };
            } else {
                break;
            }
        }

        Ok(lhs)
    }

    expr_layer_impl!(handle_expr_and, handle_expr_eq, Expr::And);
    expr_layer_impl!(handle_expr_xor, handle_expr_and, Expr::Xor);
    expr_layer_impl!(handle_expr_or, handle_expr_xor, Expr::Or);

    fn handle_expr_booland(expr: Pair<Rule>) -> Result<Expr> {
        let mut pairs = expr.into_inner();
        let mut lhs = Self::handle_expr_or(pairs.next().unwrap())?;
        loop {
            if let Some(op) = pairs.next() {
                let rhs = Self::handle_expr_or(pairs.next().unwrap())?;
                lhs = match op {
                    Rule::BOOL_AND => Expr::BoolAnd(Box::new(lhs), Box::new(rhs)),
                    Rule::BOOL_XOR => Expr::BoolXor(Box::new(lhs), Box::new(rhs)),
                    _ => unreachable!()
                }
            } else {
                break;
            }
        }

        Ok(lhs)
    }

    expr_layer_impl!(handle_expr, handle_expr_booland, Expr::BoolOr);

    fn handle_assignment(assignment: Pair<Rule>) -> Result<Statement> {
        let mut pairs = assignment.into_inner();
        let next = pairs.next().unwrap();
        if next.as_rule() == Rule::KEY_LOCAL {
            let lvalue = Self::handle_lvalue(pairs.next().unwrap())?;
            skip!(pairs); // "="
            let expr = Self::handle_expr(pairs.next().unwrap())?;
            Ok(Statement::Assignment {
                local: true,
                from: lvalue,
                to: expr
            })
        } else {
            let lvalue = Self::handle_lvalue(next)?;
            skip!(pairs); // "="
            let expr = Self::handle_expr(pairs.next().unwrap())?;
            Ok(Statement::Assignment {
                local: false,
                from: lvalue,
                to: expr
            })
        }
    }

    fn handle_statements(statements: Pair<Rule>) -> Result<Vec<Statement>> {
        let mut res = vec![];
        for statement in statements.into_inner() {
            let stmt_kind = statement.into_inner().next().unwrap();
            match stmt_kind.as_rule() {
                Rule::assignment => {
                    res.push(Self::handle_assignment(stmt_kind)?);
                },
                _ => unimplemented!("statements")
            }
        }

        Ok(res)
    }

    fn handle_semanticbody(semanticbody: Pair<Rule>) -> Result<Vec<Statement>> {
        // "{ semantic }
        let mut pairs = semanticbody.into_inner();
        skip!(pairs); // "{"
        Self::handle_statements(pairs.next().unwrap())
    }

    fn handle_macrodef(macrodef: Pair<Rule>) -> Result<PcodeMacro> {
        // "macro ID (ARGS) BODY"
        let mut pairs = macrodef.into_inner();
        skip!(pairs); // "macro"
        let name = next_str!(pairs);
        skip!(pairs); // "("
        let args = Self::handle_arguments(pairs.next().unwrap())?;
        skip!(pairs); // ")"
        let body = Self::handle_semanticbody(pairs.next().unwrap())?;
        Ok(PcodeMacro {
            name: name,
            args: args,
            sem_body: body
        })
    }

    fn handle_withblock(mut withblock: Pair<Rule>) -> Result<WithBlock> {
        // "with ID : BITPAT [context] { constructorlikelist }"
        let mut pairs = withblock.into_inner();
        skip!(pairs); // "with"
        let name = next_str!(pairs);
        let name = if name == "" { None } else { Some(name) };
        skip!(pairs); // ":"
        unimplemented!("bitpat then")
    }

    #[allow(dead_code)]
    pub(crate) fn from_parsed(mut spec: Pairs<Rule>) -> Result<Self> {
        //let mut defs = Vec::new();
        let spec = &mut spec.next()
            .ok_or(Error::EmptySpec)?
            .into_inner();
        let endian = Self::handle_endian(spec.next().ok_or(Error::EndianNotFound)?)?;
        let mut defs = Vec::new();
        //let mut cons = Vec::new();
        let mut macros = Vec::new();
        let mut withs = Vec::new();
        for span in spec {
            match span.as_rule() {
                Rule::definition => {
                    defs.push(Self::handle_def(span));
                },
                Rule::constructorlike => {
                    let kind = span.into_inner().next().unwrap();
                    match kind.as_rule() {
                        Rule::macrodef => {
                            macros.push(Self::handle_macrodef(kind));
                        },
                        Rule::withblock => {
                            withs.push(Self::handle_withblock(kind));
                        },
                        _ => unimplemented!("constructorlike: withblock, constructor")
                    };
                },
                _ => {
                    unreachable!()
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

#[test]
fn test_expr_contruct() {
    use crate::parser::{SleighParser, Rule};
    let s = "1 & 1 & 1";
    let spec = SleighParser::parse(Rule::expr, &s).unwrap();
    println!("{:?}", spec);
}
