use crate::{
    pre_parser::{
        Rule, SleighPreprocessParser
    },
    error::*,
};
use std::{
    io::{self, BufRead},
    fs::File,
    collections::HashMap
};
use pest::{
    iterators::Pair,
    Parser
};
use regex::{
    Regex, NoExpand
};

#[derive(Clone, Debug, Copy, PartialEq, Eq)]
enum Op {
    BoolOr,
    BoolAnd,
    Equal,
    NotEqual,
    None,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Value {
    Const(String),
    Bool(bool),
    None
}

impl Value {
    fn bool_op(&self, other: &Value) -> Result<(bool, bool)> {
        if let &Value::Bool(b) = self {
            if let &Value::Bool(b2) = other {
                return Ok((b, b2));
            }
        }

        Err(Error::InvalidExpr {
            msg: "can't use bool operation on non booleans".to_string()
        })
    }

    fn bool_or(&self, other: &Value) -> Result<Value> {
        let ops = self.bool_op(other)?;
        Ok(Value::Bool(ops.0 || ops.1))
    }

    fn bool_and(&self, other: &Value) -> Result<Value> {
        let ops = self.bool_op(other)?;
        Ok(Value::Bool(ops.0 && ops.1))
    }

    fn const_equal(&self, other: &str) -> Result<Value> {
        if let Value::Const(s) = self {
            Ok(Value::Bool(s == other))
        } else {
            Err(Error::InvalidExpr {
                msg: "can't use \"==\" on non-constants in macro".to_string()
            })
        }
    }

    fn const_equal_val(&self, other: &Value) -> Result<Value> {
        if let Value::Const(s) = other {
            self.const_equal(&s)
        } else {
            Err(Error::InvalidExpr {
                msg: "can't use \"==\" on non-constants in macro".to_string()
            })
        }
    }

    fn const_not_equal(&self, other: &str) -> Result<Value> {
        if let Value::Const(s) = self {
            Ok(Value::Bool(s != other))
        } else {
            Err(Error::InvalidExpr {
                msg: "can't use \"!=\" on non-constants in macro".to_string()
            })
        }
    }

    fn const_not_equal_val(&self, other: &Value) -> Result<Value> {
        if let Value::Const(s) = other {
            self.const_not_equal(&s)
        } else {
            Err(Error::InvalidExpr {
                msg: "can't use \"!=\" on non-constants in macro".to_string()
            })
        }
    }
}

fn preprocess_include(filename: &str) -> Result<Vec<String>> {
    let file = File::open(filename).map_err(|_| Error::InvalidInclude {
        filename: filename.to_string()
    })?;
    let mut lines = Vec::new();
    for line in io::BufReader::new(file).lines() {
        lines.push(line.map_err(|_| Error::InvalidInclude {
            filename: filename.to_string()
        })?);
    }
    Ok(lines)
}

fn evaluate_expr(constants: &HashMap<&str, &str>, expr: Pair<Rule>) -> Result<Value> {
    let inner = expr.into_inner();
    let mut current = Value::None;
    let mut op = Op::None;
    for each in inner {
        match each.as_rule() {
            Rule::if_expr => {
                let res = evaluate_expr(constants, each)?;
                match op {
                    Op::None => current = res,
                    Op::BoolOr => current = current.bool_or(&res)?,
                    Op::BoolAnd => current = current.bool_and(&res)?,
                    Op::Equal => current = current.const_equal_val(&res)?,
                    Op::NotEqual => current = current.const_equal_val(&res)?,
                }
            },
            Rule::defined => {
                let mut inner = each.into_inner();
                let ident = inner.next().unwrap().as_str();
                let mut res = false;
                if let Some(_) = constants.get(ident) {
                    res = true;
                } else {
                    res = false;
                }

                match op {
                    Op::None => current = Value::Bool(res),
                    Op::BoolOr => current = current.bool_or(&Value::Bool(res))?,
                    Op::BoolAnd => current = current.bool_and(&Value::Bool(res))?,
                    Op::Equal => current = current.const_equal_val(&Value::Bool(res))?,
                    Op::NotEqual => current = current.const_not_equal_val(&Value::Bool(res))?,
                }
            },
            Rule::if_bool_op => {
                let s = each.as_str();
                if s == "||" {
                    op = Op::BoolOr;
                } else {
                    op = Op::BoolAnd;
                }
            },
            Rule::if_comp_op => {
                let s = each.as_str();
                if s == "==" {
                    op = Op::Equal;
                } else {
                    op = Op::NotEqual;
                }
            },
            Rule::identifier | Rule::string => {
                let res = match each.as_rule() {
                    Rule::identifier => {
                        let ident = each.as_str();
                        if let Some(res) = constants.get(ident) {
                            res
                        } else {
                            return Err(Error::UndefinedSymbol {
                                symbol: ident.to_string(),
                            });
                        }
                    },
                    Rule::string => {
                        let s = each.as_str();
                        &s[1..s.len() - 1]
                    },
                    _ => panic!("impossible")
                };
                match op {
                    Op::None => current = Value::Const(res.to_string()),
                    Op::Equal => current = current.const_equal(res)?,
                    Op::NotEqual => current = current.const_not_equal(res)?,
                    _ => return Err(Error::InvalidExpr {
                        msg: "can't use bool operations on non-booleans".to_string()
                    }),
                }
            },
            _ => panic!("evaluate if-expr in macro but presented {:?}", each),
        }
    }

    Ok(current)
}

fn preprocess_check_expr(constants: &HashMap<&str, &str>, expr: Pair<Rule>) -> Result<bool> {
    let res = evaluate_expr(constants, expr)?;
    match res {
        Value::Bool(b) => {
            Ok(b)
        },
        _ => {
            Err(Error::InvalidExpr {
                msg: "expected boolean result in macro if condition, but got non-boolean".to_string()
            })
        }
    }
}

pub fn preprocess(src: String, defaults: HashMap<&str, &str>) -> Result<String> {
    let mut preprocessed = Vec::new();
    let mut constants = defaults.clone();
    let mut constants_regex = HashMap::new();

    for (ident, _) in constants.iter() {
        constants_regex.insert(*ident, Regex::new(&format!(r"\$\({}\)", ident)).unwrap());
    }

    let mut ignore = false;
    let mut ignore_else = false;

    let mut line_num = 0;
    let mut has_included = false;
    for line in src.split("\n") {
        line_num += 1;
        if line.starts_with("@") {
            let macro_option = SleighPreprocessParser::parse(Rule::preprocess_line, &line)
                .map_err(|_| Error::InvalidPreprocessMacro {
                    line: line.to_string(),
                    line_num: line_num
                })?
            .next()
                .unwrap();
            match macro_option.as_rule() {
                Rule::include => {
                    if ignore {
                        continue;
                    }
                    has_included = true;
                    let filename = macro_option.into_inner().next().unwrap().as_str();
                    preprocessed.extend(preprocess_include(filename)?)
                },
                Rule::def => {
                    if ignore {
                        continue;
                    }
                    let mut temp = macro_option.into_inner();
                    let ident = temp.next().unwrap().as_str();
                    let s = temp.next().unwrap().as_str();
                    let s = &s[1..s.len() - 1];
                    constants.insert(ident, s);
                    constants_regex.insert(ident, Regex::new(&format!(r"\$\({}\)", ident)).unwrap());
                },
                Rule::undef => {
                    if ignore {
                        continue;
                    }
                    let ident = macro_option.into_inner().next().unwrap().as_str();
                    constants.remove(ident);
                    constants_regex.remove(ident);
                },
                Rule::ifdef => {
                    if ignore {
                        continue;
                    }
                    let ident = macro_option.into_inner().next().unwrap().as_str();
                    if constants.get(ident).is_some() {
                        ignore = false;
                        ignore_else = true;
                    } else {
                        ignore = true;
                        ignore_else = false;
                    }
                },
                Rule::ifndef => {
                    if ignore {
                        continue;
                    }
                    let ident = macro_option.into_inner().next().unwrap().as_str();
                    if constants.get(ident).is_none() {
                        ignore = false;
                        ignore_else = true;
                    } else {
                        ignore = true;
                        ignore_else = false;
                    }
                },
                Rule::endif => {
                    ignore = false;
                },
                Rule::else_line => {
                    if ignore {
                        ignore = false;
                    } else if ignore_else {
                        ignore = true;
                        ignore_else = false;
                    } else {
                        return Err(Error::InvalidPreprocessElse {
                            line: line.to_string(),
                            line_num: line_num
                        });
                    }
                },
                Rule::if_line => {
                    if ignore {
                        continue;
                    }

                    let expr = macro_option.into_inner().next().unwrap();
                    if preprocess_check_expr(&constants, expr)? {
                        ignore = false;
                        ignore_else = true;
                    } else {
                        ignore = true;
                        ignore_else = false;
                    }
                },
                Rule::elif_line => {
                    if ignore {
                        let expr = macro_option.into_inner().next().unwrap();
                        if preprocess_check_expr(&constants, expr)? {
                            ignore = false;
                            ignore_else = true;
                        }
                    } else if ignore_else {
                        ignore = true;
                        ignore_else = false;
                    } else {
                        return Err(Error::InvalidPreprocessElse {
                            line: line.to_string(),
                            line_num: line_num
                        });
                    }
                },
                _ => { panic!("this pattern should not appear here in \"{}\"", macro_option.into_inner().as_str()) }
            }
        } else if !ignore {
            // substitution
            let mut after = line.to_string();
            for (k, re) in constants_regex.iter() {
                let val = constants.get(k).unwrap();
                after = re.replace_all(&after, NoExpand(val)).to_string();
            }
            preprocessed.push(after);
        }
    }

    let res = preprocessed.join("\n");
    let res = if has_included {
        preprocess(res, defaults)?
    } else {
        res
    };

    Ok(res)
}

#[test]
fn test_preprocess() {
    let s = r#"@define ENDIAN "little"
define endian $(ENDIAN)"#;
    assert_eq!("define endian little", preprocess(s.to_string(), HashMap::new()).unwrap());

    let s = r#"@define ENDIAN "little"
@ifdef ENDIAN
define endian $(ENDIAN)
@endif"#;
    assert_eq!("define endian little", preprocess(s.to_string(), HashMap::new()).unwrap());

    let s = r#"@define ENDIAN "little"
@ifndef ENDIAN
define endian
@else
define endian $(ENDIAN)
@endif"#;
    assert_eq!("define endian little", preprocess(s.to_string(), HashMap::new()).unwrap());

    let s = r#"@define ENDIAN "little"
@if ENDIAN == "little"
define endian $(ENDIAN)
@endif"#;
    assert_eq!("define endian little", preprocess(s.to_string(), HashMap::new()).unwrap());

    let s = r#"@define ENDIAN "little"
@if defined(ENDIAN) && (ENDIAN == "little")
define endian $(ENDIAN)
@endif"#;
    assert_eq!("define endian little", preprocess(s.to_string(), HashMap::new()).unwrap());

    let s = r#"@define ENDIAN "little"
@if defined(ENDIAN) && (ENDIAN != "little")
define endian $(ENDIAN)
@endif"#;
    assert_eq!("", preprocess(s.to_string(), HashMap::new()).unwrap());

    let s = r#"@define NAN_FP				"FPSR[24,1]"
$(NAN_FP)"#;
    assert_eq!("FPSR[24,1]", preprocess(s.to_string(), HashMap::new()).unwrap());
}
