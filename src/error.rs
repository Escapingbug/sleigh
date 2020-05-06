use std::fmt;

#[derive(Clone, Debug)]
pub enum Error {
    UndefinedSymbol {
        symbol: String,
    },
    EndianNotFound,
    EmptySpec,
    InvalidExpr {
        msg: String
    },
    InvalidPreprocessElse {
        line: String,
        line_num: usize
    },
    InvalidPreprocessMacro {
        line: String,
        line_num: usize,
    },
    InvalidInclude {
        filename: String
    },
    Unknown,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::EndianNotFound => write!(f, "Endianness definition is not found or is not the first valid definition."),
            Error::EmptySpec => write!(f, "Specification is empty"),
            Error::UndefinedSymbol {
                symbol
            } => write!(f, "undefined symbol \"{}\"", symbol),
            Error::InvalidExpr { msg } => write!(f, "Invalid expression: {}", msg),
            Error::InvalidPreprocessMacro {
                line, line_num
            } => {
                write!(f, "line {} \"{}\" contains invalid preprocess macro", line_num, line)
            },
            Error::InvalidInclude {
                filename
            } => write!(f, "{} not found while including it", filename),
            Error::InvalidPreprocessElse {
                line, line_num
            } => write!(f, "line {} \"{}\" has else case, but no corresponding if or ifdef", line, line_num),
            Error::Unknown => {
                write!(f, "unknown error")
            },
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

pub type Result<T> = std::result::Result<T, Error>;
