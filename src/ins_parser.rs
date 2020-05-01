use crate::{
    instruction::*,
    error::*
};

pub trait SingleInsParser {
    /// parse current stream of a single instruction, return an instruction and next
    fn parse_ins<'s, B: Into<u8>>(s: &[B]) -> Option<(Instruction, &[B])>;
}

pub trait InsParser: Iterator<Item=Instruction> {}
