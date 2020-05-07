use std::{
    fmt,
    num::ParseIntError
};
use snailquote::UnescapeError;

#[derive(Debug)]
pub enum Error {
    UndefinedSymbol {
        symbol: String,
    },
    InvalidVarAttachField,
    InvalidStringLiteral(UnescapeError),
    EndianNotFound,
    EmptySpec,
    UnknownSpace {
        space: String
    },
    ParseIntError(ParseIntError),
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
            Error::UnknownSpace { space } => write!(f, "space name {} unknown", space),
            Error::InvalidVarAttachField => write!(f, "attach variables fields cannot be wildcard"),
            Error::InvalidStringLiteral(e) => write!(f, "Invalid string literal {}", e),
            Error::EndianNotFound => write!(f, "Endianness definition is not found or is not the first valid definition."),
            Error::ParseIntError(e) => write!(f, "Parse int errored with: {} This might be caused by integer constant too long, currently only 64-bit integer is supported yet", e),
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
        match self {
            Self::ParseIntError(e) => Some(e),
            Self::InvalidStringLiteral(e) => Some(e),
            _ => None
        }
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        Self::ParseIntError(err)
    }
}

impl From<UnescapeError> for Error {
    fn from(err: UnescapeError) -> Self {
        Self::InvalidStringLiteral(err)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
