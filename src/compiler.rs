use crate::{
    instruction::*,
    error::*,
    ins_parser::*,
    parser::{
        SleighParser,
        Rule,
    },
    preprocess,
};
use std::collections::HashMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InsParserSetup {
}

#[derive(Clone, Debug, Default)]
pub struct InsParserSetupBuilder {

}

#[derive(Clone)]
pub struct SleighCompiler {
    src: String,
    builder: InsParserSetupBuilder,
}

impl SleighCompiler {
    pub fn new(src: String) -> Self {
        Self {
            src: src,
            builder: InsParserSetupBuilder::default(),
        }
    }

    fn preprocess(&mut self) -> Result<()> {
        let mut temp = String::new();
        std::mem::swap(&mut self.src, &mut temp);
        self.src = preprocess::preprocess(temp, HashMap::new())?;
        Ok(())
    }

    fn init(&mut self) {
        unimplemented!()
    }

    pub fn compile(&self)-> InsParserSetup {
        unimplemented!()
    }
}
