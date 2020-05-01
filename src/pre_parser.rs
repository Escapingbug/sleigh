use pest::Parser;

#[derive(Parser)]
#[grammar = "sleigh_preprocess.pest"]
pub struct SleighPreprocessParser;

#[cfg(test)]
fn test_parse(s: &str, rule: Rule, do_print: bool) {
    let res = SleighPreprocessParser::parse(rule, s);
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
fn test_preprocess_parse() {
    let parse = |s| test_parse(s, Rule::preprocess_line, true);

    parse(r#"@if defined(ENDIAN) && (ENDIAN != "little")"#);
}
