#![allow(deprecated)]
#![allow(unused_variables)]

extern crate rand; //旧版，可以改
use rand::Rng;
use regex_syntax::ast::parse::Parser;
use regex_syntax::ast::{Ast, ClassSet, ClassSetBinaryOpKind, ClassSetItem}; //导入多个，解析器和语法树

use once_cell::sync::Lazy;
use std::sync::Arc; //多线程共享数据 //全局变量的惰性初始化

use fancy_regex::Regex as FancyRegex;
use onig::Regex as OnigRegex;
use rand_regex::Regex as RandRegex;
use regex::Regex as StdRegex;
use regex_lite::Regex as LiteRegex;

// 第一部分：统一接口定义

pub trait RegexMatcher: Send + Sync {
    fn is_match(&self, text: &str) -> bool;
    fn name(&self) -> &'static str;
}

pub trait RegexCompiler: Send + Sync {
    fn compile(
        &self,
        pattern: &str,
    ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>;
    fn name(&self) -> &'static str;
}

#[derive(Debug)]
pub struct LibCompilationError {
    pattern: String,
    errors: Vec<(&'static str, String)>,
}

impl std::fmt::Display for LibCompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Failed to compile pattern '{}' in any library:",
            self.pattern
        )?;
        for (lib, err) in &self.errors {
            write!(f, "\n  {}: {}", lib, err)?;
        }
        Ok(())
    }
}

impl std::error::Error for LibCompilationError {}

#[derive(Debug)]
pub enum ComparisonError {
    // 差分转写和编译不通过
    PreCheckFailed {
        pattern: String,
        errors: Vec<(String, String)>,
    },
    // 无法生成差分测试需要的input
    TestStringsGenerationFailed {
        pattern: String,
    },
    // 差分结果不一致
    DifferentialMismatch {
        pattern: String,
        test_string: String,
        // (库名, 库对应的模式, 是否匹配)
        errors: Vec<(String, String, bool)>,
    },
    // 蜕变结果不一致
    MetamorphicMismatch {
        pattern: String,
        errors: Vec<(String, String)>,
    },
    // Egraph生成等价表达式无法全部通过编译(可能是解析错误也可能是编译不通过)
    EgraphPreCheckFailed {
        pattern: String,
        errors: Vec<(String, String)>,
    },
    // Egraph生成等价表达式行为不一致
    EgraphMismatch {
        pattern: String,
        test_string: String,
        errors: Vec<(String, bool)>,
    },
    // 无法找到对应引擎
    CompilerNotFound {
        name: String,
    },
}

impl std::fmt::Display for ComparisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonError::PreCheckFailed { pattern, errors } => {
                writeln!(f, "[PRE-CHECK] 模式预检查失败")?;
                writeln!(f, "  模式: {:?}", pattern)?;
                write!(f, "  错误: ")?;
                for (i, (name, err)) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}={}", name, err)?;
                }
                Ok(())
            }
            ComparisonError::TestStringsGenerationFailed { pattern } => {
                writeln!(f, "[TEST STRING GENERATION] 测试字符串生成失败")?;
                writeln!(f, "  模式: {:?}", pattern)?;
                Ok(())
            }
            ComparisonError::DifferentialMismatch {
                pattern,
                test_string,
                errors,
            } => {
                writeln!(f, "[DIFFERENTIAL] 差分测试失败")?;
                writeln!(f, "  模式: {:?}", pattern)?;
                writeln!(f, "  测试字符串: {:?}", test_string)?;
                for (i, (name, pat, err)) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}({}): {}", name, pat, err)?;
                }
                Ok(())
            }
            ComparisonError::MetamorphicMismatch { pattern, errors } => {
                writeln!(f, "[METAMORPHIC] 蜕变测试失败")?;
                writeln!(f, "  模式: {:?}", pattern)?;
                for (i, (name, err)) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}={}", name, err)?;
                }
                Ok(())
            }
            ComparisonError::EgraphPreCheckFailed { pattern, errors } => {
                writeln!(f, "[EGRAPH] 预校验失败")?;
                writeln!(f, "  模式: {:?}", pattern)?;
                for (i, (name, err)) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}={}", name, err)?;
                }
                Ok(())
            }
            ComparisonError::EgraphMismatch {
                pattern,
                test_string,
                errors,
            } => {
                writeln!(f, "[EGRAPH] 等价表达式行为不一致")?;
                writeln!(f, "  模式: {:?}", pattern)?;
                writeln!(f, "  测试字符串: {:?}", test_string)?;
                for (i, (name, err)) in errors.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}={}", name, err)?;
                }
                Ok(())
            }
            ComparisonError::CompilerNotFound { name } => {
                writeln!(f, "[EGRAPH] 未找到对应引擎")?;
                writeln!(f, "  引擎: {:?}", name)?;
                Ok(())
            }
        }
    }
}

impl std::error::Error for ComparisonError {}

// 第二部分：各个库的适配器实现
mod std_regex {
    use super::*;

    pub struct StdRegexCompiler;

    impl RegexCompiler for StdRegexCompiler {
        fn compile(
            &self,
            pattern: &str,
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>
        {
            let re = StdRegex::new(pattern)?;
            Ok(Box::new(StdRegexMatcher(re)))
        }

        fn name(&self) -> &'static str {
            "regex"
        }
    }

    struct StdRegexMatcher(StdRegex);

    impl RegexMatcher for StdRegexMatcher {
        fn is_match(&self, text: &str) -> bool {
            self.0.is_match(text)
        }

        fn name(&self) -> &'static str {
            "regex"
        }
    }
}

mod lite_regex {
    use super::*;

    pub struct LiteRegexCompiler;

    impl RegexCompiler for LiteRegexCompiler {
        fn compile(
            &self,
            pattern: &str,
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>
        {
            let re = LiteRegex::new(pattern)?;
            Ok(Box::new(LiteRegexMatcher(re)))
        }

        fn name(&self) -> &'static str {
            "regex-lite"
        }
    }

    struct LiteRegexMatcher(LiteRegex);

    impl RegexMatcher for LiteRegexMatcher {
        fn is_match(&self, text: &str) -> bool {
            self.0.is_match(text)
        }

        fn name(&self) -> &'static str {
            "regex-lite"
        }
    }
}

mod fancy_regex_adapter {
    use super::*;

    pub struct FancyRegexCompiler;

    impl RegexCompiler for FancyRegexCompiler {
        fn compile(
            &self,
            pattern: &str,
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>
        {
            let re = FancyRegex::new(pattern)?;
            Ok(Box::new(FancyRegexMatcher(re)))
        }

        fn name(&self) -> &'static str {
            "fancy-regex"
        }
    }

    struct FancyRegexMatcher(FancyRegex);

    impl RegexMatcher for FancyRegexMatcher {
        fn is_match(&self, text: &str) -> bool {
            self.0.is_match(text).unwrap_or(false)
        }

        fn name(&self) -> &'static str {
            "fancy-regex"
        }
    }
}

mod onig_regex {
    use super::*;

    pub struct OnigRegexCompiler;

    impl RegexCompiler for OnigRegexCompiler {
        fn compile(
            &self,
            pattern: &str,
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>
        {
            let re = OnigRegex::new(pattern)?;
            Ok(Box::new(OnigRegexMatcher(re)))

            // let result = std::panic::catch_unwind(|| OnigRegex::new(pattern));
            // match result {
            //     Ok(Ok(re)) => Ok(Box::new(OnigRegexMatcher(re))),
            //     Ok(Err(e)) => Err(Box::new(e)),
            //     Err(_) => Err("onig panicked".into()),
            // }
        }

        fn name(&self) -> &'static str {
            "onig"
        }
    }

    struct OnigRegexMatcher(OnigRegex);

    impl RegexMatcher for OnigRegexMatcher {
        fn is_match(&self, text: &str) -> bool {
            self.0.is_match(text)
        }

        fn name(&self) -> &'static str {
            "onig"
        }
    }
}

mod pcre2_regex {
    use super::*;

    pub struct Pcre2RegexCompiler;

    impl RegexCompiler for Pcre2RegexCompiler {
        fn compile(
            &self,
            pattern: &str,
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>
        {
            let re =
                pcre2::bytes::RegexBuilder::new().utf(true).build(pattern)?;
            Ok(Box::new(Pcre2RegexMatcher(re)))
        }

        fn name(&self) -> &'static str {
            "pcre2"
        }
    }

    struct Pcre2RegexMatcher(pcre2::bytes::Regex);

    impl RegexMatcher for Pcre2RegexMatcher {
        fn is_match(&self, text: &str) -> bool {
            self.0.is_match(text.as_bytes()).unwrap_or(false)
        }

        fn name(&self) -> &'static str {
            "pcre2"
        }
    }
}

mod regex_automata_adapter {
    use super::*;
    use regex_automata::dfa::{dense, regex};

    pub struct RegexAutomataCompiler;

    impl RegexCompiler for RegexAutomataCompiler {
        fn compile(
            &self,
            pattern: &str,
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>
        {
            let re = regex::Regex::builder()
                .dense(
                    dense::Config::new().dfa_size_limit(Some(5 * 1024 * 1024)),
                )
                .build(pattern)?;

            Ok(Box::new(RegexAutomataMatcher(re)))
        }

        fn name(&self) -> &'static str {
            "regex-automata"
        }
    }

    struct RegexAutomataMatcher(regex_automata::dfa::regex::Regex);

    impl RegexMatcher for RegexAutomataMatcher {
        fn is_match(&self, text: &str) -> bool {
            self.0.is_match(text.as_bytes())
        }

        fn name(&self) -> &'static str {
            "regex-automata"
        }
    }
}

//第三部分：正则表达式库管理器
pub struct RegexLibManager {
    compilers: Vec<Box<dyn RegexCompiler>>,
    baseline_priority: Vec<&'static str>,
}

impl RegexLibManager {
    pub fn new() -> Self {
        let compilers: Vec<Box<dyn RegexCompiler>> = vec![
            Box::new(std_regex::StdRegexCompiler),
            Box::new(lite_regex::LiteRegexCompiler),
            Box::new(fancy_regex_adapter::FancyRegexCompiler),
            Box::new(onig_regex::OnigRegexCompiler),
            Box::new(pcre2_regex::Pcre2RegexCompiler),
            Box::new(regex_automata_adapter::RegexAutomataCompiler),
        ];

        let baseline_priority = vec![
            "regex",
            "regex-lite",
            "regex-automata",
            "fancy-regex",
            "onig",
            "pcre2",
        ];

        Self { compilers, baseline_priority }
    }

    pub fn set_baseline_priority(&mut self, priority: Vec<&'static str>) {
        self.baseline_priority = priority;
    }

    pub fn get_compilers(&self) -> &[Box<dyn RegexCompiler>] {
        &self.compilers
    }
    pub fn get_compiler(&self, name: &str) -> Option<&Box<dyn RegexCompiler>> {
        self.compilers.iter().find(|c| c.name() == name)
    }

    pub fn get_baseline<'a>(
        &self,
        compiled: &'a [(
            &'static str,
            Arc<dyn (Fn(&str) -> bool) + Send + Sync>,
        )],
    ) -> Option<(&'static str, Arc<dyn (Fn(&str) -> bool) + Send + Sync>)>
    {
        self.baseline_priority.iter().find_map(|&name| {
            compiled
                .iter()
                .find(|(n, _)| n == &name)
                .map(|(n, m)| (*n, Arc::clone(m)))
        })
    }
}

// 第四部分：AST框架

trait AstTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String>;
}

#[derive(Clone)]
struct TranslatorOptions {
    library: &'static str,
    supports_unicode_classes: bool,
    supports_named_groups: bool,
    supports_lookaround: bool,
    supports_start_end_assertions: bool,
}

fn translate_ast(
    ast: &Ast,
    options: TranslatorOptions,
) -> Result<String, String> {
    match ast {
        Ast::Empty(_) => Ok(String::new()),

        Ast::Literal(lit) => Ok(translate_literal(lit, &options)),

        Ast::Concat(concat) => {
            let parts: Result<Vec<String>, String> = concat
                .asts
                .iter()
                .map(|a| translate_ast(a, options.clone()))
                .collect();
            parts.map(|v| v.join(""))
        }

        Ast::Alternation(alt) => {
            let parts: Result<Vec<String>, String> = alt
                .asts
                .iter()
                .map(|a| translate_ast(a, options.clone()))
                .collect();
            parts.map(|v| {
                if v.len() == 1 {
                    v[0].clone()
                } else {
                    format!("(?:{})", v.join("|"))
                }
            })
        }

        Ast::Group(g) => {
            let inner = translate_ast(&g.ast, options.clone())?;

            match &g.kind {
                regex_syntax::ast::GroupKind::CaptureIndex(_) => {
                    Ok(format!("({})", inner))
                }
                regex_syntax::ast::GroupKind::CaptureName { name, .. } => {
                    if !options.supports_named_groups {
                        // 检查模式中是否使用了这个命名组作为反向引用
                        if contains_named_backreference(&g.ast, &name.name) {
                            return Err(
                                format!(
                                    "库 {} 不支持命名捕获组，但模式中使用了命名组 '{}' 作为反向引用",
                                    options.library,
                                    name.name
                                )
                            );
                        }
                        return Err(format!(
                            "库 {} 不支持命名捕获组 '{}'",
                            options.library, name.name
                        ));
                    }

                    match options.library {
                        "regex" | "regex-lite" | "regex-automata" => {
                            Ok(format!("(?P<{}>{})", name.name, inner))
                        }
                        "pcre2" | "onig" | "fancy-regex" => {
                            Ok(format!("(?<{}>{})", name.name, inner))
                        }
                        _ => Err(format!(
                            "库 {} 不支持命名捕获组",
                            options.library
                        )),
                    }
                }
                regex_syntax::ast::GroupKind::NonCapturing(_) => {
                    Ok(format!("(?:{})", inner))
                }
            }
        }

        Ast::Repetition(rep) => {
            let inner = translate_ast(&rep.ast, options.clone())?;
            Ok(translate_repetition(rep, &inner, &options))
        }

        Ast::Assertion(assert) => {
            match &assert.kind {
                regex_syntax::ast::AssertionKind::StartLine => Ok("^".into()),
                regex_syntax::ast::AssertionKind::EndLine => Ok("$".into()),
                regex_syntax::ast::AssertionKind::StartText => {
                    if !options.supports_start_end_assertions {
                        return Err(format!(
                            "库 {} 不支持 \\A 断言",
                            options.library
                        ));
                    }
                    Ok(r"\A".into())
                }
                regex_syntax::ast::AssertionKind::EndText => {
                    if !options.supports_start_end_assertions {
                        return Err(format!(
                            "库 {} 不支持 \\z 断言",
                            options.library
                        ));
                    }
                    Ok(r"\z".into())
                }
                regex_syntax::ast::AssertionKind::WordBoundary => {
                    Ok(r"\b".into())
                }
                regex_syntax::ast::AssertionKind::NotWordBoundary => {
                    Ok(r"\B".into())
                }
                _ => {
                    // 处理所有查找断言（Lookaround）
                    if !options.supports_lookaround {
                        return Err(format!(
                            "库 {} 不支持查找断言",
                            options.library
                        ));
                    }
                    Err(format!("库 {} 需要实现查找断言支持", options.library))
                }
            }
        }

        Ast::Dot(_) => Ok(".".to_string()),

        Ast::Flags(flags) => {
            let mut flag_str = String::from("(?");

            for item in &flags.flags.items {
                match &item.kind {
                    regex_syntax::ast::FlagsItemKind::Flag(flag) => {
                        match flag {
                            regex_syntax::ast::Flag::CaseInsensitive => {
                                flag_str.push('i');
                            }
                            regex_syntax::ast::Flag::MultiLine => {
                                flag_str.push('m');
                            }
                            regex_syntax::ast::Flag::DotMatchesNewLine => {
                                match options.library {
                                    "regex" | "regex-lite"
                                    | "regex-automata" | "pcre2" | "onig"
                                    | "fancy-regex" => flag_str.push('s'),
                                    _ => {
                                        return Err(format!(
                                            "库 {} 不支持 's' 标志",
                                            options.library
                                        ));
                                    }
                                }
                            }
                            regex_syntax::ast::Flag::SwapGreed => {
                                match options.library {
                                    "regex" | "regex-lite"
                                    | "regex-automata" | "pcre2" | "onig"
                                    | "fancy-regex" => flag_str.push('U'),
                                    _ => {
                                        return Err(format!(
                                            "库 {} 不支持 'U' 标志",
                                            options.library
                                        ));
                                    }
                                }
                            }
                            regex_syntax::ast::Flag::IgnoreWhitespace => {
                                match options.library {
                                    "regex" | "fancy-regex" | "pcre2"
                                    | "onig" => flag_str.push('x'),
                                    _ => {
                                        return Err(format!(
                                            "库 {} 不支持 'x' 标志",
                                            options.library
                                        ));
                                    }
                                }
                            }
                            regex_syntax::ast::Flag::Unicode => {
                                if !options.supports_unicode_classes {
                                    return Err(format!(
                                        "库 {} 不支持 'u' (Unicode) 标志",
                                        options.library
                                    ));
                                }
                                flag_str.push('u');
                            }
                            _ => {
                                return Err(format!(
                                    "库 {} 不支持标志 {:?}",
                                    options.library, flag
                                ));
                            }
                        }
                    }
                    regex_syntax::ast::FlagsItemKind::Negation => {
                        flag_str.push('-');
                    }
                }
            }

            flag_str.push(')');
            Ok(flag_str)
        }

        Ast::ClassUnicode(class) => translate_unicode_class(class, &options),

        Ast::ClassPerl(class) => translate_perl_class(class, &options),

        Ast::ClassBracketed(bracketed) => {
            translate_bracketed_class(bracketed, &options)
        }
    }
}

/// 检查AST中是否包含对命名组的反向引用
fn contains_named_backreference(ast: &Ast, name: &str) -> bool {
    match ast {
        Ast::Concat(concat) => {
            concat.asts.iter().any(|a| contains_named_backreference(a, name))
        }
        Ast::Alternation(alt) => {
            alt.asts.iter().any(|a| contains_named_backreference(a, name))
        }
        Ast::Repetition(rep) => contains_named_backreference(&rep.ast, name),
        Ast::Group(group) => contains_named_backreference(&group.ast, name),
        _ => false,
    }
}

/// 翻译字面量字符
fn translate_literal(
    lit: &regex_syntax::ast::Literal,
    options: &TranslatorOptions,
) -> String {
    let c = lit.c;
    match c {
        '\\' | '^' | '$' | '.' | '|' | '?' | '*' | '+' | '(' | ')' | '['
        | ']' | '{' | '}' | '-' => {
            format!(r"\{}", c)
        }
        // '-' if options.library == "onig" => {
        //     // eprintln!("Escaping '-' for onig");
        //     format!(r"\{}", c)
        // }
        _ => c.to_string(),
    }
}

/// 翻译重复模式
fn translate_repetition(
    rep: &regex_syntax::ast::Repetition,
    inner: &str,
    options: &TranslatorOptions,
) -> String {
    let quant = match &rep.op.kind {
        regex_syntax::ast::RepetitionKind::ZeroOrOne => "?".to_string(),
        regex_syntax::ast::RepetitionKind::ZeroOrMore => "*".to_string(),
        regex_syntax::ast::RepetitionKind::OneOrMore => "+".to_string(),
        regex_syntax::ast::RepetitionKind::Range(range) => match range {
            regex_syntax::ast::RepetitionRange::Exactly(m) => {
                format!("{{{}}}", m)
            }
            regex_syntax::ast::RepetitionRange::AtLeast(m) => {
                format!("{{{},}}", m)
            }
            regex_syntax::ast::RepetitionRange::Bounded(m, n) => {
                format!("{{{},{}}}", m, n)
            }
        },
    };

    let greedy = if rep.greedy { "" } else { "?" };

    let needs_group = match rep.ast.as_ref() {
        Ast::Literal(_)
        | Ast::Dot(_)
        | Ast::ClassUnicode(_)
        | Ast::ClassPerl(_) => false,
        _ => true,
    };

    if needs_group {
        format!("(?:{}){}{}", inner, quant, greedy)
    } else {
        format!("{}{}{}", inner, quant, greedy)
    }
}

/// 翻译Unicode字符类
fn translate_unicode_class(
    class: &regex_syntax::ast::ClassUnicode,
    options: &TranslatorOptions,
) -> Result<String, String> {
    match &class.kind {
        regex_syntax::ast::ClassUnicodeKind::OneLetter(letter) => {
            match letter {
                'w' | 'd' | 's' | 'W' | 'D' | 'S' => {
                    // 这些字符类在大多数库中都支持
                    Ok(format!(r"\{}", letter))
                }
                _ => {
                    // 其他单个字母的Unicode字符类
                    if !options.supports_unicode_classes {
                        return Err(format!(
                            "库 {} 不支持Unicode字符类 \\{}",
                            options.library, letter
                        ));
                    }
                    Ok(format!(r"\{}", letter))
                }
            }
        }
        regex_syntax::ast::ClassUnicodeKind::Named(name) => {
            if !options.supports_unicode_classes {
                return Err(format!(
                    "库 {} 不支持Unicode属性 \\p{{{}}}",
                    options.library, name
                ));
            }
            Ok(format!(r"\p{{{}}}", name))
        }
        regex_syntax::ast::ClassUnicodeKind::NamedValue { name, .. } => {
            if !options.supports_unicode_classes {
                return Err(format!(
                    "库 {} 不支持Unicode属性值 \\p{{{}}}",
                    options.library, name
                ));
            }
            Ok(format!(r"\p{{{}}}", name))
        }
    }
}

/// 翻译Perl字符类
fn translate_perl_class(
    class: &regex_syntax::ast::ClassPerl,
    options: &TranslatorOptions,
) -> Result<String, String> {
    match &class.kind {
        regex_syntax::ast::ClassPerlKind::Digit => {
            match options.library {
                "regex-lite" => {
                    // 仅补充全角数字
                    // 0-9: ASCII 数字
                    // \u{FF10}-\u{FF19}: 全角数字 (０-１-２...９)
                    let digits = "0-9\u{FF10}-\u{FF19}";

                    if class.negated {
                        // \D -> [^0-9０-９]
                        Ok(format!("[^{}]", digits))
                    } else {
                        // \d -> [0-9０-９]
                        Ok(format!("[{}]", digits))
                    }
                }
                _ => {
                    // 标准库直接用 \d 或 \D
                    if class.negated {
                        Ok(r"\D".to_string())
                    } else {
                        Ok(r"\d".to_string())
                    }
                }
            }
        }
        regex_syntax::ast::ClassPerlKind::Space => match options.library {
            "regex-lite" => {
                // 仅补充常见的 Unicode 空白字符
                let spaces = r" \t\n\r\f\v\u0085\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000";
                if class.negated {
                    Ok(format!("[^{}]", spaces))
                } else {
                    Ok(format!("[{}]", spaces))
                }
            }
            _ => {
                if class.negated {
                    Ok(r"\S".to_string())
                } else {
                    Ok(r"\s".to_string())
                }
            }
        },
        regex_syntax::ast::ClassPerlKind::Word => Ok(r"\w".to_string()),
    }
}

/// 翻译括号字符类 `[...]`。
/// 当前 fuzz 已经过滤掉所有包含 `&` 的模式，因此这里不再区分是否有交集，
/// 统一使用 `regex-syntax` 的 Printer 将 AST 打印回字符串。
fn translate_bracketed_class(
    bracketed: &regex_syntax::ast::ClassBracketed,
    options: &TranslatorOptions,
) -> Result<String, String> {
    let mut buf = String::new();
    let class_set_str = translate_class_set(&bracketed.kind, options)?;
    buf.push('[');
    if bracketed.negated {
        buf.push('^');
    }
    buf.push_str(&class_set_str);
    buf.push(']');
    Ok(buf)
}
/// 递归翻译 ClassSetItem
fn translate_class_set_item(
    item: &ClassSetItem,
    options: &TranslatorOptions,
) -> Result<String, String> {
    match item {
        ClassSetItem::Empty(_) => {
            // 空字符类，在 PCRE/Onig 不允许，使用 [^\0] 代替
            Ok("^\\0".to_string())
        }
        ClassSetItem::Literal(lit) => Ok(translate_literal(lit, options)),
        ClassSetItem::Range(range) => Ok(format!(
            "{}-{}",
            translate_literal(&range.start, options),
            translate_literal(&range.end, options)
        )),
        ClassSetItem::Ascii(ascii) => {
            let kind_str = format!("{:?}", ascii.kind).to_lowercase();
            if ascii.negated {
                Ok(format!("[:^{}:]", kind_str))
            } else {
                Ok(format!("[:{}:]", kind_str))
            }
        }
        ClassSetItem::Unicode(unicode) => {
            translate_unicode_class(unicode, options)
        }
        ClassSetItem::Perl(perl) => translate_perl_class(perl, options),
        ClassSetItem::Bracketed(inner) => {
            translate_bracketed_class(inner, options)
        }
        ClassSetItem::Union(union) => {
            // 对于 fuzzer 过滤掉了交集，直接遍历 union.items
            let mut buf = String::new();
            for subitem in &union.items {
                buf.push_str(&translate_class_set_item(subitem, options)?);
            }
            Ok(buf)
        }
    }
}
fn translate_class_set(
    classSetItem: &ClassSet,
    options: &TranslatorOptions,
) -> Result<String, String> {
    let mut buf = String::new();
    match &classSetItem {
        ClassSet::Item(item) => {
            buf.push_str(&translate_class_set_item(&item, options)?);
        }
        ClassSet::BinaryOp(op) => {
            let lhs = translate_class_set(op.lhs.as_ref(), options)?;
            let rhs = translate_class_set(op.rhs.as_ref(), options)?;
            let kind = match &op.kind {
                ClassSetBinaryOpKind::Intersection => "&&",
                ClassSetBinaryOpKind::Difference => "--",
                ClassSetBinaryOpKind::SymmetricDifference => "~~",
            };
            buf.push_str(&lhs);
            buf.push_str(&kind);
            buf.push_str(&rhs);
        }
    }
    Ok(buf)
}
// 第五部分：Translator实现

struct RegexTranslator;
impl AstTranslator for RegexTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(
            ast,
            TranslatorOptions {
                library: "regex",
                supports_unicode_classes: true,
                supports_named_groups: true,
                supports_lookaround: false,
                supports_start_end_assertions: true,
            },
        )
    }
}

struct RegexLiteTranslator;
impl AstTranslator for RegexLiteTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(
            ast,
            TranslatorOptions {
                library: "regex-lite",
                supports_unicode_classes: false,
                supports_named_groups: false,
                supports_lookaround: false,
                supports_start_end_assertions: true,
            },
        )
    }
}

struct RegexAutomataTranslator;
impl AstTranslator for RegexAutomataTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(
            ast,
            TranslatorOptions {
                library: "regex-automata",
                supports_unicode_classes: true,
                supports_named_groups: true,
                supports_lookaround: false,
                supports_start_end_assertions: true,
            },
        )
    }
}

struct FancyRegexTranslator;
impl AstTranslator for FancyRegexTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(
            ast,
            TranslatorOptions {
                library: "fancy-regex",
                supports_unicode_classes: true,
                supports_named_groups: true,
                supports_lookaround: true,
                supports_start_end_assertions: true,
            },
        )
    }
}

struct OnigTranslator;
impl AstTranslator for OnigTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(
            ast,
            TranslatorOptions {
                library: "onig",
                supports_unicode_classes: true,
                supports_named_groups: true,
                supports_lookaround: true,
                supports_start_end_assertions: true,
            },
        )
    }
}

struct Pcre2Translator;
impl AstTranslator for Pcre2Translator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(
            ast,
            TranslatorOptions {
                library: "pcre2",
                supports_unicode_classes: true,
                supports_named_groups: true,
                supports_lookaround: true,
                supports_start_end_assertions: true,
            },
        )
    }
}

// 第六部分：辅助函数与过滤

const RAND_REGEX_REPEAT_LIMIT: u32 = 16;

fn contains_unsupported_features(ast: &Ast) -> bool {
    use regex_syntax::ast::*;

    match ast {
        Ast::ClassPerl(_) => true,
        Ast::ClassUnicode(_) => true,
        Ast::Assertion(assertion) => {
            // 检查是否为查找断言
            match assertion.kind {
                AssertionKind::StartLine
                | AssertionKind::EndLine
                | AssertionKind::StartText
                | AssertionKind::EndText
                | AssertionKind::WordBoundary
                | AssertionKind::NotWordBoundary => false,
                _ => true, // 其他断言类型视为不支持
            }
        }
        Ast::Flags(_) => true,
        Ast::Concat(concat) => {
            concat.asts.iter().any(|a| contains_unsupported_features(a))
        }
        Ast::Alternation(alt) => {
            alt.asts.iter().any(|a| contains_unsupported_features(a))
        }
        Ast::Repetition(rep) => contains_unsupported_features(&rep.ast),
        Ast::Group(group) => contains_unsupported_features(&group.ast),
        _ => false,
    }
}

fn contains_large_repetition(ast: &Ast, limit: u32) -> bool {
    use regex_syntax::ast::*;

    match ast {
        // 当前节点是重复，则先检查自身的量词是否超限，再递归其子 AST
        Ast::Repetition(rep) => {
            repetition_is_large(rep, limit)
                || contains_large_repetition(&rep.ast, limit)
        }

        // 这些节点需要递归检查子节点
        Ast::Concat(concat) => {
            concat.asts.iter().any(|a| contains_large_repetition(a, limit))
        }
        Ast::Alternation(alt) => {
            alt.asts.iter().any(|a| contains_large_repetition(a, limit))
        }
        Ast::Group(group) => contains_large_repetition(&group.ast, limit),

        // 其它节点不包含重复量词
        _ => false,
    }
}

fn repetition_is_large(
    rep: &regex_syntax::ast::Repetition,
    limit: u32,
) -> bool {
    use regex_syntax::ast::{RepetitionKind, RepetitionRange};

    match &rep.op.kind {
        // ?, *, + 这种不看具体次数，当前阶段不认为是“过大”
        RepetitionKind::ZeroOrOne
        | RepetitionKind::ZeroOrMore
        | RepetitionKind::OneOrMore => false,

        // {N} / {N,} / {N,M} 的情况
        RepetitionKind::Range(range) => match range {
            RepetitionRange::Exactly(m) => (*m as u32) > limit,
            RepetitionRange::AtLeast(m) => (*m as u32) > limit,
            RepetitionRange::Bounded(m, n) => {
                (*m as u32) > limit || (*n as u32) > limit
            }
        },
    }
}

pub fn contains_unsupported_perl(pattern: &str) -> bool {
    let mut chars = pattern.chars().peekable();
    let mut escaped = false;

    while let Some(c) = chars.next() {
        if escaped {
            escaped = false;
            continue;
        }

        if c == '\\' {
            if let Some(&next) = chars.peek() {
                match next {
                    'w' | 'W' | 'd' | 'D' | 's' | 'S' => return true,
                    _ => {}
                }
            }
            escaped = true;
        }
    }

    false
}

pub fn gen_multiple_accepted_strings(
    pattern: &str,
    count: usize,
) -> Vec<String> {
    let mut ret = vec![];
    let regex = match RandRegex::compile(pattern, RAND_REGEX_REPEAT_LIMIT) {
        Ok(r) => r,
        Err(_) => {
            return ret;
        }
    };
    let mut rng = rand::thread_rng();
    for _ in 0..count {
        let sample: String = rng.sample(&regex);
        ret.push(sample);
    }
    ret
}

/// 根据库名返回对应的 AST 翻译器
fn get_translator_for(lib: &str) -> Option<Box<dyn AstTranslator>> {
    match lib {
        "regex" => Some(Box::new(RegexTranslator)),
        "regex-lite" => Some(Box::new(RegexLiteTranslator)),
        "regex-automata" => Some(Box::new(RegexAutomataTranslator)),
        "fancy-regex" => Some(Box::new(FancyRegexTranslator)),
        "onig" => Some(Box::new(OnigTranslator)),
        "pcre2" => Some(Box::new(Pcre2Translator)),
        _ => None,
    }
}

/**
 * 差分测试：验证给定模式在多个正则表达式库中的行为一致性
 */
pub fn validate_pattern(
    manager: &RegexLibManager,
    pattern: &str,
    ast: &Ast,
    hasUnicode:bool
) -> Result<(), ComparisonError> {
    let mut compiled: Vec<(
        &'static str,
        String,
        Arc<dyn (Fn(&str) -> bool) + Send + Sync>,
    )> = Vec::new();
    let mut errors: Vec<(String, String)> = Vec::new();

    // 对每个库：先 AST 翻译，再调用该库的编译器
    for compiler in manager.get_compilers() {
        let lib_name = compiler.name();
        // 暂时跳过 pcre2，不参与 diff 比较
        if lib_name == "pcre2" {
            continue;
        }
        if hasUnicode{
            let unsupported_regex=["regex-lite","regex-automata","regex-literal","safe-regex","regex-cursor"];
            if unsupported_regex.contains(&lib_name){
                println!("pattern：{} 包含unicode匹配项，引擎：{}跳过",pattern,lib_name);
                continue;
            }
        }
        // 取对应的 AST 翻译器
        let translator = match get_translator_for(lib_name) {
            Some(t) => t,
            None => {
                continue;
            }
        };

        // 把统一 AST 翻译成该库能理解的正则字符串
        let pattern_for_lib = match translator.translate(ast) {
            Ok(p) => p,
            Err(e) => {
                errors.push((
                    lib_name.to_string(),
                    format!("AST translate failed: {}", e),
                ));
                continue;
            }
        };

        // 用该库自己的编译器编译翻译后的模式
        match compiler.compile(&pattern_for_lib) {
            Ok(matcher) => {
                let mfn: Arc<dyn (Fn(&str) -> bool) + Send + Sync> =
                    Arc::new(move |text: &str| matcher.is_match(text));
                compiled.push((lib_name, pattern_for_lib, mfn));
            }
            Err(e) => {
                errors.push((
                    lib_name.to_string(),
                    format!("compile failed: {}", e),
                ));
                continue;
            }
        }
    }
    if !errors.is_empty() {
        return Err(ComparisonError::PreCheckFailed {
            pattern: pattern.to_string(),
            errors: errors,
        });
    }

    // 仍然用原始 pattern（regex 语法）生成若干匹配样本串
    let test_strings = gen_multiple_accepted_strings(pattern, 100);
    if test_strings.is_empty() {
        return Err(ComparisonError::TestStringsGenerationFailed {
            pattern: pattern.to_string(),
        });
    }

    // 多库行为对比
    for test_str in &test_strings {
        // 3.1 收集当前字符串在所有库上的运行结果
        // 结果格式: Vec<(库名, 库对应的模式, 是否匹配)>
        let current_results: Vec<(String, String, bool)> = compiled
            .iter()
            .map(|(lib_name, pattern_for_lib, matcher)| {
                (
                    lib_name.to_string(),
                    pattern_for_lib.clone(),
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(
                        || matcher(test_str),
                    ))
                    .unwrap_or(false),
                )
            })
            .collect();

        // 3.2 检查一致性
        if let Some((first_lib, first_pat, first_result)) =
            current_results.first()
        {
            let is_consistent =
                current_results.iter().all(|(_, _, res)| res == first_result);
            if !is_consistent {
                // 3.3 发现不一致，构造详细报告
                return Err(ComparisonError::DifferentialMismatch {
                    pattern: pattern.to_string(),
                    test_string: test_str.clone(),
                    errors: current_results, // 记录所有库的结果
                });
            }
        }
    }

    Ok(())
}
/**
 * 给定模式已通过前置检验，确定可以被各库编译。
 * 验证正则表达式库在多个给定模式的行为一致性
 * 蜕变测试
 */
pub fn validate_regexLib(
    manager: &RegexLibManager,
    pattern: &str,
) -> Result<(), ComparisonError> {
    let mut errors: Vec<(String, String)> = Vec::new();
    for compiler in manager.get_compilers() {
        let lib_name = compiler.name();
        if lib_name == "pcre2" {
            continue;
        }
        // 取对应的 AST 翻译器
        let translator = match get_translator_for(lib_name) {
            Some(t) => t,
            None => {
                continue;
            }
        };
        // Convert pattern to ast
        let ast = match Parser::new().parse(&pattern) {
            Ok(ast) => ast,
            Err(_) => {
                return Err(ComparisonError::EgraphPreCheckFailed {
                    pattern: pattern.to_string(),
                    errors: errors,
                });
            } // Invalid pattern, skip this input
        };
        // 把统一 AST 翻译成该库能理解的正则字符串
        let pattern_for_lib = match translator.translate(&ast) {
            Ok(p) => p,
            Err(e) => {
                errors.push((
                    lib_name.to_string(),
                    format!("AST translate failed: {}", e),
                ));
                continue;
            }
        };
        match compiler.compile(&pattern_for_lib) {
            Ok(matcher) => {}
            Err(e) => {
                errors.push((
                    lib_name.to_string(),
                    format!("compile failed: {}", e),
                ));
            }
        }
    }
    if !errors.is_empty() {
        return Err(ComparisonError::MetamorphicMismatch {
            pattern: pattern.to_string(),
            errors: errors,
        });
    }
    Ok(())
}
/*
 * 验证等价模式在regex引擎下的行为一致性
 */
pub fn validate_eq_patterns(
    manager: &RegexLibManager,
    pattern: &str,
    eq_patterns: &[String],
) -> Result<(), ComparisonError> {
    let mut compiled: Vec<(
        String,
        Arc<dyn (Fn(&str) -> bool) + Send + Sync>,
    )> = Vec::new();
    let mut errors: Vec<(String, String)> = Vec::new();

    // Egraph生成等价表达式预校验：是否可以通过编译
    let compiler = manager.get_compiler("regex").ok_or_else(|| {
        ComparisonError::CompilerNotFound { name: "regex".to_string() }
    })?;
    for eq_pattern in eq_patterns {
        match compiler.compile(&eq_pattern) {
            Ok(matcher) => {
                let pat = eq_pattern.clone();
                let mfn: Arc<dyn (Fn(&str) -> bool) + Send + Sync> =
                    Arc::new(move |text: &str| matcher.is_match(text));
                compiled.push((pat, mfn));
            }
            Err(e) => {
                errors.push((
                    eq_pattern.clone(),
                    format!("compile failed: {}", e),
                ));
                continue;
            }
        }
    }
    if !errors.is_empty() {
        return Err(ComparisonError::EgraphPreCheckFailed {
            pattern: pattern.to_string(),
            errors: errors,
        });
    }

    // Egraph生成等价表达式行为对比
    let test_strings = gen_multiple_accepted_strings(pattern, 100);
    if test_strings.is_empty() {
        return Err(ComparisonError::TestStringsGenerationFailed {
            pattern: pattern.to_string(),
        });
    }
    for test_str in &test_strings {
        // 结果格式: Vec<(模式字符串, 是否匹配)>
        let current_results: Vec<(String, bool)> = compiled
            .iter()
            .map(|(pat, matcher)| (pat.clone(), matcher(test_str)))
            .collect();

        // 3.2 检查一致性
        if let Some((first_lib, first_result)) = current_results.first() {
            let is_consistent =
                current_results.iter().all(|(_, res)| res == first_result);
            if !is_consistent {
                // 3.3 发现不一致，构造详细报告
                return Err(ComparisonError::EgraphMismatch {
                    pattern: pattern.to_string(),
                    test_string: test_str.clone(),
                    errors: current_results, // 记录所有表达式的结果
                });
            }
        }
    }
    Ok(())
}

// 第八部分：全局管理器初始化

static REGEX_LIB_MANAGER: Lazy<RegexLibManager> = Lazy::new(|| {
    let mut manager = RegexLibManager::new();

    if let Ok(priority) = std::env::var("REGEX_BASELINE_PRIORITY") {
        let priority_list: Vec<&'static str> = priority
            .split(',')
            .map(|s| match s.trim() {
                "regex" => "regex",
                "regex-lite" => "regex-lite",
                "fancy-regex" => "fancy-regex",
                "onig" => "onig",
                "pcre2" => "pcre2",
                "regex-automata" => "regex-automata",
                _ => "regex",
            })
            .collect();

        if !priority_list.is_empty() {
            manager.set_baseline_priority(priority_list);
        }
    }

    manager
});
