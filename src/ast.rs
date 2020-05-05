//! Sleigh language ASTs
use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// This is the root for internal(crate-wise) usage for easy the life of implementing semantic
/// analysis and generating InterpIr which serves the purpose of generating AST for interpretation
/// during instruction parsing.
///
/// TL;DR : InterpIr is the refined IR (with tables and ASTs) of RawAst.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub(crate) struct RawRoot {
    pub(crate) defs: Vec<Definition>,
    pub(crate) cons: Vec<Constructor>,
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
        bits: u64,
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
    pub bits: u64,
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
impl Default for FieldDisplay {
    fn default() -> Self {
        Self::Hex
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ContextField {
    pub name: String,
    pub from: u64,
    pub bits: u64,
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
    pub bits: u64,
}
