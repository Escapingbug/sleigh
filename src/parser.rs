use pest::Parser;

#[derive(Parser)]
#[grammar = "sleigh.pest"]
pub struct SleighParser;



#[cfg(test)]
fn test_parse(s: &str, rule: Rule, do_print: bool) {
    let res = SleighParser::parse(rule, s);
    if do_print {
        if let Err(e) = res.clone() {
            println!("{}", e);
        } else {
            println!("{}", res.as_ref().unwrap());
        }
    }
    res.unwrap();
}

#[test]
fn test_parser() {
    //test_parse("#\n", Rule::test, true);
}

#[test]
fn test_qstring() {
    let parse = |s| test_parse(s, Rule::qstring, false);
    parse("\"abc\"");
    parse("\"\\t\"");
    parse("\"\\\"\"");
}

#[test]
fn test_identifier() {
    let parse = |s| test_parse(s, Rule::identifier, false);
    parse("RAM");
}


#[test]
fn test_spec() {
    use std::io::Read;
    use std::fs::File;
    let mut spec = File::open("test/test.spec").unwrap();
    let mut s = String::new();
    spec.read_to_string(&mut s).unwrap();

    let parse = |s| test_parse(s, Rule::spec, false);
    parse(&s);
}

#[test]
fn test_define_space() {
    let parse = |s| test_parse(s, Rule::definition, true);
    parse("define space RAM type=ram_space  size=2  default;");
}
