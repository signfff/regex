#![no_main]
#![allow(deprecated)]
#![allow(unused_variables)]
mod differential_testing;
extern crate rand; //旧版，可以改
use rand::Rng;
use regex_syntax::ast::{ parse::Parser, Ast }; //导入多个，解析器和语法树

use libfuzzer_sys::{ fuzz_target, fuzz_mutator, Corpus };
use std::sync::Arc; //多线程共享数据
use once_cell::sync::Lazy; //全局变量的惰性初始化

use rand_regex::Regex as RandRegex;
use regex::Regex as StdRegex;
use regex_lite::Regex as LiteRegex;
use fancy_regex::Regex as FancyRegex;
use onig::Regex as OnigRegex;

// 第一部分：统一接口定义

pub trait RegexMatcher: Send + Sync {
    fn is_match(&self, text: &str) -> bool;
    fn name(&self) -> &'static str;
}

pub trait RegexCompiler: Send + Sync {
    fn compile(&self, pattern: &str) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>>;
    fn name(&self) -> &'static str;
}

#[derive(Debug)]
pub struct LibCompilationError {
    pattern: String,
    errors: Vec<(&'static str, String)>,
}

impl std::fmt::Display for LibCompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Failed to compile pattern '{}' in any library:", self.pattern)?;
        for (lib, err) in &self.errors {
            write!(f, "\n  {}: {}", lib, err)?;
        }
        Ok(())
    }
}

impl std::error::Error for LibCompilationError {}

#[derive(Debug)]
pub enum ComparisonError {
    CompilationFailed(LibCompilationError),
    NoBaselineFound,
    MismatchFound {
        pattern: String,
        test_string: String,
        baseline: (String, bool),
        mismatched: (&'static str, bool),
        all_results: Vec<(&'static str, bool)>,
    },
}

impl std::fmt::Display for ComparisonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ComparisonError::CompilationFailed(e) => { write!(f, "库编译失败: {}", e) }
            ComparisonError::NoBaselineFound => { write!(f, "未找到基准库") }
            ComparisonError::MismatchFound {
                pattern,
                test_string,
                baseline,
                mismatched,
                all_results,
            } => {
                writeln!(f, "[LIB-DIFF] 正则表达式库行为不一致")?;
                writeln!(f, "  模式: {:?}", pattern)?;
                writeln!(f, "  测试字符串: {:?}", test_string)?;
                writeln!(f, "  基准库({}): {}", baseline.0, baseline.1)?;
                writeln!(f, "  不匹配的库({}): {}", mismatched.0, mismatched.1)?;
                write!(f, "  所有库结果: ")?;
                for (i, (name, result)) in all_results.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}={}", name, result)?;
                }
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
            pattern: &str
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>> {
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
            pattern: &str
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>> {
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
            pattern: &str
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>> {
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
            pattern: &str
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>> {
            let re = OnigRegex::new(pattern)?;
            Ok(Box::new(OnigRegexMatcher(re)))
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
            pattern: &str
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>> {
            let re = pcre2::bytes::RegexBuilder::new().utf(true).build(pattern)?;
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
    use regex_automata::dfa::regex::Builder;

    pub struct RegexAutomataCompiler;

    impl RegexCompiler for RegexAutomataCompiler {
        fn compile(
            &self,
            pattern: &str
        ) -> Result<Box<dyn RegexMatcher>, Box<dyn std::error::Error>> {
            let re = Builder::new().build(pattern)?;
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
            Box::new(regex_automata_adapter::RegexAutomataCompiler)
        ];

        let baseline_priority = vec![
            "regex",
            "regex-lite",
            "regex-automata",
            "fancy-regex",
            "onig",
            "pcre2"
        ];

        Self {
            compilers,
            baseline_priority,
        }
    }

    pub fn set_baseline_priority(&mut self, priority: Vec<&'static str>) {
        self.baseline_priority = priority;
    }

    pub fn get_compilers(&self) -> &[Box<dyn RegexCompiler>] {
        &self.compilers
    }

    pub fn get_baseline<'a>(
        &self,
        compiled: &'a [(&'static str, Arc<dyn (Fn(&str) -> bool) + Send + Sync>)]
    ) -> Option<(&'static str, Arc<dyn (Fn(&str) -> bool) + Send + Sync>)> {
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

fn translate_ast(ast: &Ast, options: TranslatorOptions) -> Result<String, String> {
    match ast {
        Ast::Empty(_) => Ok(String::new()),

        Ast::Literal(lit) => Ok(translate_literal(lit, &options)),

        Ast::Concat(concat) => {
            let parts: Result<Vec<String>, String> = concat.asts
                .iter()
                .map(|a| translate_ast(a, options.clone()))
                .collect();
            parts.map(|v| v.join(""))
        }

        Ast::Alternation(alt) => {
            let parts: Result<Vec<String>, String> = alt.asts
                .iter()
                .map(|a| translate_ast(a, options.clone()))
                .collect();
            parts.map(|v| {
                if v.len() == 1 { v[0].clone() } else { format!("(?:{})", v.join("|")) }
            })
        }

        Ast::Group(g) => {
            let inner = translate_ast(&g.ast, options.clone())?;

            match &g.kind {
                regex_syntax::ast::GroupKind::CaptureIndex(_) => Ok(format!("({})", inner)),
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
                        return Err(
                            format!("库 {} 不支持命名捕获组 '{}'", options.library, name.name)
                        );
                    }

                    match options.library {
                        "regex" | "regex-lite" | "regex-automata" => {
                            Ok(format!("(?P<{}>{})", name.name, inner))
                        }
                        "pcre2" | "onig" | "fancy-regex" => {
                            Ok(format!("(?<{}>{})", name.name, inner))
                        }
                        _ => Err(format!("库 {} 不支持命名捕获组", options.library)),
                    }
                }
                regex_syntax::ast::GroupKind::NonCapturing(_) => Ok(format!("(?:{})", inner)),
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
                        return Err(format!("库 {} 不支持 \\A 断言", options.library));
                    }
                    Ok(r"\A".into())
                }
                regex_syntax::ast::AssertionKind::EndText => {
                    if !options.supports_start_end_assertions {
                        return Err(format!("库 {} 不支持 \\z 断言", options.library));
                    }
                    Ok(r"\z".into())
                }
                regex_syntax::ast::AssertionKind::WordBoundary => Ok(r"\b".into()),
                regex_syntax::ast::AssertionKind::NotWordBoundary => Ok(r"\B".into()),
                _ => {
                    // 处理所有查找断言（Lookaround）
                    if !options.supports_lookaround {
                        return Err(format!("库 {} 不支持查找断言", options.library));
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
                            regex_syntax::ast::Flag::CaseInsensitive => flag_str.push('i'),
                            regex_syntax::ast::Flag::MultiLine => flag_str.push('m'),
                            regex_syntax::ast::Flag::DotMatchesNewLine => {
                                match options.library {
                                    | "regex"
                                    | "regex-lite"
                                    | "regex-automata"
                                    | "pcre2"
                                    | "onig"
                                    | "fancy-regex" => flag_str.push('s'),
                                    _ => {
                                        return Err(
                                            format!("库 {} 不支持 's' 标志", options.library)
                                        );
                                    }
                                }
                            }
                            regex_syntax::ast::Flag::SwapGreed => {
                                match options.library {
                                    | "regex"
                                    | "regex-lite"
                                    | "regex-automata"
                                    | "pcre2"
                                    | "onig"
                                    | "fancy-regex" => flag_str.push('U'),
                                    _ => {
                                        return Err(
                                            format!("库 {} 不支持 'U' 标志", options.library)
                                        );
                                    }
                                }
                            }
                            regex_syntax::ast::Flag::IgnoreWhitespace => {
                                match options.library {
                                    "regex" | "fancy-regex" | "pcre2" | "onig" =>
                                        flag_str.push('x'),
                                    _ => {
                                        return Err(
                                            format!("库 {} 不支持 'x' 标志", options.library)
                                        );
                                    }
                                }
                            }
                            regex_syntax::ast::Flag::Unicode => {
                                if !options.supports_unicode_classes {
                                    return Err(
                                        format!("库 {} 不支持 'u' (Unicode) 标志", options.library)
                                    );
                                }
                                flag_str.push('u');
                            }
                            _ => {
                                return Err(format!("库 {} 不支持标志 {:?}", options.library, flag));
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

        Ast::ClassBracketed(bracketed) => translate_bracketed_class(bracketed, &options),
    }
}

/// 检查AST中是否包含对命名组的反向引用
fn contains_named_backreference(ast: &Ast, name: &str) -> bool {
    match ast {
        Ast::Concat(concat) => { concat.asts.iter().any(|a| contains_named_backreference(a, name)) }
        Ast::Alternation(alt) => { alt.asts.iter().any(|a| contains_named_backreference(a, name)) }
        Ast::Repetition(rep) => { contains_named_backreference(&rep.ast, name) }
        Ast::Group(group) => { contains_named_backreference(&group.ast, name) }
        _ => false,
    }
}

/// 翻译字面量字符
fn translate_literal(lit: &regex_syntax::ast::Literal, options: &TranslatorOptions) -> String {
    let c = lit.c;

    match c {
        '\\' | '^' | '$' | '.' | '|' | '?' | '*' | '+' | '(' | ')' | '[' | ']' | '{' | '}' => {
            format!(r"\{}", c)
        }
        _ => c.to_string(),
    }
}

/// 翻译重复模式
fn translate_repetition(
    rep: &regex_syntax::ast::Repetition,
    inner: &str,
    options: &TranslatorOptions
) -> String {
    let quant = match &rep.op.kind {
        regex_syntax::ast::RepetitionKind::ZeroOrOne => "?".to_string(),
        regex_syntax::ast::RepetitionKind::ZeroOrMore => "*".to_string(),
        regex_syntax::ast::RepetitionKind::OneOrMore => "+".to_string(),
        regex_syntax::ast::RepetitionKind::Range(range) =>
            match range {
                regex_syntax::ast::RepetitionRange::Exactly(m) => format!("{{{}}}", m),
                regex_syntax::ast::RepetitionRange::AtLeast(m) => format!("{{{},}}", m),
                regex_syntax::ast::RepetitionRange::Bounded(m, n) => format!("{{{},{}}}", m, n),
            }
    };

    let greedy = if rep.greedy { "" } else { "?" };

    let needs_group = match rep.ast.as_ref() {
        Ast::Literal(_) | Ast::Dot(_) | Ast::ClassUnicode(_) | Ast::ClassPerl(_) => false,
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
    options: &TranslatorOptions
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
                        return Err(
                            format!("库 {} 不支持Unicode字符类 \\{}", options.library, letter)
                        );
                    }
                    Ok(format!(r"\{}", letter))
                }
            }
        }
        regex_syntax::ast::ClassUnicodeKind::Named(name) => {
            if !options.supports_unicode_classes {
                return Err(format!("库 {} 不支持Unicode属性 \\p{{{}}}", options.library, name));
            }
            Ok(format!(r"\p{{{}}}", name))
        }
        regex_syntax::ast::ClassUnicodeKind::NamedValue { name, .. } => {
            if !options.supports_unicode_classes {
                return Err(format!("库 {} 不支持Unicode属性值 \\p{{{}}}", options.library, name));
            }
            Ok(format!(r"\p{{{}}}", name))
        }
    }
}

/// 翻译Perl字符类
fn translate_perl_class(
    class: &regex_syntax::ast::ClassPerl,
    options: &TranslatorOptions
) -> Result<String, String> {
    match &class.kind {
        regex_syntax::ast::ClassPerlKind::Digit => Ok(r"\d".to_string()),
        regex_syntax::ast::ClassPerlKind::Space => Ok(r"\s".to_string()),
        regex_syntax::ast::ClassPerlKind::Word => Ok(r"\w".to_string()),
    }
}

/// 翻译括号字符类 `[...]`。
/// 当前 fuzz 已经过滤掉所有包含 `&` 的模式，因此这里不再区分是否有交集，
/// 统一使用 `regex-syntax` 的 Printer 将 AST 打印回字符串。
fn translate_bracketed_class(
    bracketed: &regex_syntax::ast::ClassBracketed,
    _options: &TranslatorOptions
) -> Result<String, String> {
    use regex_syntax::ast::Ast;

    let ast = Ast::ClassBracketed(Box::new(bracketed.clone()));
    let mut printed = String::new();
    regex_syntax::ast::print::Printer
        ::new()
        .print(&ast, &mut printed)
        .map_err(|e| format!("无法打印字符类 AST: {}", e))?;

    Ok(printed)
}
// 第五部分：Translator实现

struct RegexTranslator;
impl AstTranslator for RegexTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(ast, TranslatorOptions {
            library: "regex",
            supports_unicode_classes: true,
            supports_named_groups: true,
            supports_lookaround: false,
            supports_start_end_assertions: true,
        })
    }
}

struct RegexLiteTranslator;
impl AstTranslator for RegexLiteTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(ast, TranslatorOptions {
            library: "regex-lite",
            supports_unicode_classes: false,
            supports_named_groups: false,
            supports_lookaround: false,
            supports_start_end_assertions: true,
        })
    }
}

struct RegexAutomataTranslator;
impl AstTranslator for RegexAutomataTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(ast, TranslatorOptions {
            library: "regex-automata",
            supports_unicode_classes: true,
            supports_named_groups: true,
            supports_lookaround: false,
            supports_start_end_assertions: true,
        })
    }
}

struct FancyRegexTranslator;
impl AstTranslator for FancyRegexTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(ast, TranslatorOptions {
            library: "fancy-regex",
            supports_unicode_classes: true,
            supports_named_groups: true,
            supports_lookaround: true,
            supports_start_end_assertions: true,
        })
    }
}

struct OnigTranslator;
impl AstTranslator for OnigTranslator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(ast, TranslatorOptions {
            library: "onig",
            supports_unicode_classes: true,
            supports_named_groups: true,
            supports_lookaround: true,
            supports_start_end_assertions: true,
        })
    }
}

struct Pcre2Translator;
impl AstTranslator for Pcre2Translator {
    fn translate(&self, ast: &Ast) -> Result<String, String> {
        translate_ast(ast, TranslatorOptions {
            library: "pcre2",
            supports_unicode_classes: true,
            supports_named_groups: true,
            supports_lookaround: true,
            supports_start_end_assertions: true,
        })
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
                | AssertionKind::StartLine
                | AssertionKind::EndLine
                | AssertionKind::StartText
                | AssertionKind::EndText
                | AssertionKind::WordBoundary
                | AssertionKind::NotWordBoundary => false,
                _ => true, // 其他断言类型视为不支持
            }
        }
        Ast::Flags(_) => true,
        Ast::Concat(concat) => { concat.asts.iter().any(|a| contains_unsupported_features(a)) }
        Ast::Alternation(alt) => { alt.asts.iter().any(|a| contains_unsupported_features(a)) }
        Ast::Repetition(rep) => { contains_unsupported_features(&rep.ast) }
        Ast::Group(group) => { contains_unsupported_features(&group.ast) }
        _ => false,
    }
}

fn contains_large_repetition(ast: &Ast, limit: u32) -> bool {
    use regex_syntax::ast::*;

    match ast {
        // 当前节点是重复，则先检查自身的量词是否超限，再递归其子 AST
        Ast::Repetition(rep) => {
            repetition_is_large(rep, limit) || contains_large_repetition(&rep.ast, limit)
        }

        // 这些节点需要递归检查子节点
        Ast::Concat(concat) => concat.asts.iter().any(|a| contains_large_repetition(a, limit)),
        Ast::Alternation(alt) => alt.asts.iter().any(|a| contains_large_repetition(a, limit)),
        Ast::Group(group) => contains_large_repetition(&group.ast, limit),

        // 其它节点不包含重复量词
        _ => false,
    }
}

fn repetition_is_large(rep: &regex_syntax::ast::Repetition, limit: u32) -> bool {
    use regex_syntax::ast::{ RepetitionKind, RepetitionRange };

    match &rep.op.kind {
        // ?, *, + 这种不看具体次数，当前阶段不认为是“过大”
        RepetitionKind::ZeroOrOne | RepetitionKind::ZeroOrMore | RepetitionKind::OneOrMore => false,

        // {N} / {N,} / {N,M} 的情况
        RepetitionKind::Range(range) =>
            match range {
                RepetitionRange::Exactly(m) => (*m as u32) > limit,
                RepetitionRange::AtLeast(m) => (*m as u32) > limit,
                RepetitionRange::Bounded(m, n) => { (*m as u32) > limit || (*n as u32) > limit }
            }
    }
}

fn gen_multiple_accepted_strings(pattern: &str, count: usize) -> Vec<String> {
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

/// 使用 AST 翻译器 + 各库语法，对所有库做安全比较
fn compare_libraries_safely(
    manager: &RegexLibManager,
    pattern: &str,
    ast: &Ast
) -> Result<(), ComparisonError> {
    let mut compiled: Vec<(&'static str, Arc<dyn (Fn(&str) -> bool) + Send + Sync>)> = Vec::new();
    let mut errors: Vec<(&'static str, String)> = Vec::new();

    // 对每个库：先 AST 翻译，再调用该库的编译器
    for compiler in manager.get_compilers() {
        let lib_name = compiler.name();
        // 暂时跳过 pcre2，不参与 diff 比较
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

        // 把统一 AST 翻译成该库能理解的正则字符串
        let pattern_for_lib = match translator.translate(ast) {
            Ok(p) => p,
            Err(e) => {
                errors.push((lib_name, format!("AST translate failed: {}", e)));
                continue;
            }
        };

        // 用该库自己的编译器编译翻译后的模式
        match compiler.compile(&pattern_for_lib) {
            Ok(matcher) => {
                let name = matcher.name();
                let mfn: Arc<dyn (Fn(&str) -> bool) + Send + Sync> = Arc::new(move |text: &str|
                    matcher.is_match(text)
                );
                compiled.push((name, mfn));
            }
            Err(e) => {
                errors.push((lib_name, format!("compile failed: {}", e)));
            }
        }
    }

    // 至少需要两个库才能比较
    if compiled.len() < 2 {
        return Err(
            ComparisonError::CompilationFailed(LibCompilationError {
                pattern: pattern.to_string(),
                errors,
            })
        );
    }

    // 选择基准库
    let (baseline_name, baseline_matcher) = manager
        .get_baseline(&compiled)
        .ok_or(ComparisonError::NoBaselineFound)?;

    // 仍然用原始 pattern（regex 语法）生成若干匹配样本串
    let test_strings = gen_multiple_accepted_strings(pattern, 100);
    if test_strings.is_empty() {
        return Err(
            ComparisonError::CompilationFailed(LibCompilationError {
                pattern: pattern.to_string(),
                errors: vec![("test", "failed to generate test strings".to_string())],
            })
        );
    }

    // 多库行为对比
    for test_str in &test_strings {
        let baseline_result = baseline_matcher(test_str);

        for (lib_name, matcher) in &compiled {
            if *lib_name == baseline_name {
                continue;
            }

            let result = matcher(test_str);
            if result != baseline_result {
                return Err(ComparisonError::MismatchFound {
                    pattern: pattern.to_string(),
                    test_string: test_str.clone(),
                    baseline: (baseline_name.to_string(), baseline_result),
                    mismatched: (*lib_name, result),
                    all_results: compiled
                        .iter()
                        .map(|(n, m)| (*n, m(test_str)))
                        .collect(),
                });
            }
        }
    }

    Ok(())
}

//  第七部分：自定义Mutator

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, _seed: u32| {
    if size == 0 || max_size == 0 {
        return 0;
    }

    let mut pattern = String::from_utf8_lossy(&data[..size]).into_owned();
    let mutation_type = _seed % 17;

    match mutation_type {
        0 => {
            if !pattern.is_empty() {
                let pos = (_seed as usize) % pattern.len();
                let quantifiers = ["?", "{2,5}", "{1,3}", "{0,1}", "{1,}", "{2}", "{0,3}"];
                let q = quantifiers[(_seed as usize) % quantifiers.len()];
                pattern.insert_str(pos, q);
            }
        }
        1 => {
            let classes = ["\\d", "\\w", "\\s", "[a-z]", "[0-9]", ".", "[^a]"];
            let class = classes[(_seed as usize) % classes.len()];
            if pattern.len() < max_size - class.len() {
                let pos = if pattern.is_empty() { 0 } else { (_seed as usize) % pattern.len() };
                pattern.insert_str(pos, class);
            }
        }
        2 => {
            if !pattern.is_empty() && pattern.len() < max_size - 3 {
                let pos = (_seed as usize) % pattern.len();
                pattern.insert_str(pos, "|");
                pattern.insert(pos + 1, 'a');
            }
        }
        3 => {
            if !pattern.is_empty() && pattern.len() < max_size - 2 {
                let pos = (_seed as usize) % pattern.len();
                pattern.insert(pos, '(');
                if pos + 2 < pattern.len() {
                    pattern.insert(pos + 2, ')');
                } else {
                    pattern.push(')');
                }
            }
        }
        4 => {
            let anchors = ["^", "$", "\\b", "\\B"];
            let anchor = anchors[(_seed as usize) % anchors.len()];
            if pattern.len() < max_size - anchor.len() {
                if _seed % 2 == 0 {
                    pattern.insert_str(0, anchor);
                } else {
                    pattern.push_str(anchor);
                }
            }
        }
        5 => {
            let flags = ["(?i)", "(?m)", "(?s)", "(?x)"];
            let flag = flags[(_seed as usize) % flags.len()];
            if pattern.len() < max_size - flag.len() {
                pattern.insert_str(0, flag);
            }
        }
        6 => {
            if !pattern.is_empty() {
                let pos = (_seed as usize) % pattern.len();
                if let Some(ch) = pattern.chars().nth(pos) {
                    if ".+*?^${}[]|()\\".contains(ch) && pattern.len() < max_size {
                        pattern.insert(pos, '\\');
                    }
                }
            }
        }
        7 => {
            let unicode_classes = ["\\p{L}", "\\p{N}", "\\p{P}", "\\p{Greek}"];
            let class = unicode_classes[(_seed as usize) % unicode_classes.len()];
            if pattern.len() < max_size - class.len() {
                let pos = if pattern.is_empty() { 0 } else { (_seed as usize) % pattern.len() };
                pattern.insert_str(pos, class);
            }
        }
        8 => {
            if !pattern.is_empty() && pattern.contains('(') {
                let backrefs = ["\\1", "\\2", "\\3"];
                let backref = backrefs[(_seed as usize) % backrefs.len()];
                let pos = (_seed as usize) % pattern.len();
                pattern.insert_str(pos, backref);
            }
        }
        9 => {
            let assertions = ["(?=\\w)", "(?!\\d)", "(?<=\\s)", "(?<!\\W)"];
            let assertion = assertions[(_seed as usize) % assertions.len()];
            if pattern.len() < max_size - assertion.len() {
                let pos = if pattern.is_empty() { 0 } else { (_seed as usize) % pattern.len() };
                pattern.insert_str(pos, assertion);
            }
        }
        10 => {
            if !pattern.is_empty() && pattern.len() < max_size - 4 {
                let pos = (_seed as usize) % pattern.len();
                pattern.insert_str(pos, "(?:");
                if pos + 3 < pattern.len() {
                    pattern.insert(pos + 3, ')');
                } else {
                    pattern.push(')');
                }
            }
        }
        11 => {
            let classes = ["[a-z&&[^aeiou]]", "[\\w&&[^\\d]]", "[a-z&&[^xyz]]"];
            let class = classes[(_seed as usize) % classes.len()];
            if pattern.len() < max_size - class.len() {
                let pos = if pattern.is_empty() { 0 } else { (_seed as usize) % pattern.len() };
                pattern.insert_str(pos, class);
            }
        }
        12 => {
            if !pattern.is_empty() {
                let pos = (_seed as usize) % pattern.len();
                pattern.remove(pos);
            }
        }
        13 => {
            if !pattern.is_empty() {
                let start = (_seed as usize) % pattern.len();
                let max_len = (pattern.len() - start).max(1);
                let len = (((_seed >> 8) as usize) % max_len) + 1;
                let end = (start + len).min(pattern.len());
                pattern.drain(start..end);
            }
        }
        14 => {
            if !pattern.is_empty() && pattern.len() < max_size {
                let start = (_seed as usize) % pattern.len();
                let max_len = (pattern.len() - start).max(1);
                let len = (((_seed >> 8) as usize) % max_len) + 1;
                let end = (start + len).min(pattern.len());

                let substring = pattern[start..end].to_string();
                let repeat_count = ((_seed >> 16) % 3) + 1;

                for _ in 0..repeat_count {
                    if pattern.len() + substring.len() < max_size {
                        pattern.insert_str(end, &substring);
                    } else {
                        break;
                    }
                }
            }
        }
        _ => {
            if !pattern.is_empty() {
                let pos = (_seed as usize) % pattern.len();
                let replacements = [
                    'a',
                    '1',
                    '.',
                    '*',
                    '|',
                    '(',
                    ')',
                    '[',
                    ']',
                    '\\',
                    '{',
                    '}',
                    '-',
                    '^',
                    '$',
                ];
                let replacement = replacements[(_seed as usize) % replacements.len()];
                pattern.replace_range(pos..pos + 1, &replacement.to_string());
            }
        }
    }

    let bytes = pattern.as_bytes();
    let copy_len = std::cmp::min(bytes.len(), max_size);
    data[..copy_len].copy_from_slice(&bytes[..copy_len]);
    copy_len
});

// 第八部分：全局管理器初始化

static REGEX_LIB_MANAGER: Lazy<RegexLibManager> = Lazy::new(|| {
    let mut manager = RegexLibManager::new();

    if let Ok(priority) = std::env::var("REGEX_BASELINE_PRIORITY") {
        let priority_list: Vec<&'static str> = priority
            .split(',')
            .map(|s| {
                match s.trim() {
                    "regex" => "regex",
                    "regex-lite" => "regex-lite",
                    "fancy-regex" => "fancy-regex",
                    "onig" => "onig",
                    "pcre2" => "pcre2",
                    "regex-automata" => "regex-automata",
                    _ => "regex",
                }
            })
            .collect();

        if !priority_list.is_empty() {
            manager.set_baseline_priority(priority_list);
        }
    }

    manager
});
// TODO: 尝试将regex语法的pattern翻译为其他语法
fn translate_pattern_to_other_language(input: &[u8]) -> Corpus {
    let _ = env_logger::try_init();
    let pattern_cow = String::from_utf8_lossy(input);
    let pattern_str = pattern_cow.as_ref();

    if pattern_cow.len() < 3 || pattern_cow.len() > 100 {
        return Corpus::Reject;
    }

    // 检查是否包含连续的重复量词
    let has_consecutive_quantifiers = pattern_str
        .chars()
        .collect::<Vec<_>>()
        .windows(3)
        .any(|window| {
            window.iter().all(|&c| c == '*') ||
                window.iter().all(|&c| c == '+') ||
                window.iter().all(|&c| (c == '*' || c == '+'))
        });

    if has_consecutive_quantifiers {
        return Corpus::Reject;
    }

    let mut parser = Parser::new();

    // 先解析 AST
    let ast = match parser.parse(pattern_str) {
        Ok(ast) => ast,
        Err(_) => {
            return Corpus::Reject;
        }
    };

    //特征过滤
    // 跨库差异较大特性
    if contains_unsupported_features(&ast) {
        return Corpus::Reject;
    }
    // 重复次数过大
    if contains_large_repetition(&ast, 16) {
        return Corpus::Reject;
    }

    // 包含字符 '&'
    if pattern_str.contains('&') {
        return Corpus::Reject;
    }

    // Perl 类
    if
        pattern_str.contains("\\d") ||
        pattern_str.contains("\\D") ||
        pattern_str.contains("\\w") ||
        pattern_str.contains("\\W") ||
        pattern_str.contains("\\s") ||
        pattern_str.contains("\\S")
    {
        return Corpus::Reject;
    }

    // Unicode 属性 \p{...}
    if pattern_str.contains("\\p{") {
        return Corpus::Reject;
    }
    // 复杂嵌套字符类
    if pattern_str.contains("[[") {
        return Corpus::Reject;
    }
    match compare_libraries_safely(&REGEX_LIB_MANAGER, pattern_str, &ast) {
        Ok(()) => { Corpus::Keep }
        Err(e @ ComparisonError::MismatchFound { .. }) => {
            panic!("{}", e);
        }
        Err(ComparisonError::CompilationFailed(_)) => { Corpus::Reject }
        // 没找到基准库
        Err(ComparisonError::NoBaselineFound) => {
            eprintln!("[WARN] No baseline found for pattern: {:?}", pattern_str);
            Corpus::Keep
        }
    }
}
// 第九部分：Fuzz目标函数

fuzz_target!(|case: &[u8]| -> Corpus {
    let _ = env_logger::try_init();
    let pattern_cow = String::from_utf8_lossy(case);
    let pattern_str = pattern_cow.as_ref();

    if pattern_cow.len() < 3 || pattern_cow.len() > 100 {
        return Corpus::Reject;
    }

    // 检查是否包含连续的重复量词
    let has_consecutive_quantifiers = pattern_str
        .chars()
        .collect::<Vec<_>>()
        .windows(3)
        .any(|window| {
            window.iter().all(|&c| c == '*') ||
                window.iter().all(|&c| c == '+') ||
                window.iter().all(|&c| (c == '*' || c == '+'))
        });

    if has_consecutive_quantifiers {
        return Corpus::Reject;
    }

    let mut parser = Parser::new();

    // 先解析 AST
    let ast = match parser.parse(pattern_str) {
        Ok(ast) => ast,
        Err(_) => {
            return Corpus::Reject;
        }
    };

    //特征过滤
    // 跨库差异较大特性
    if contains_unsupported_features(&ast) {
        return Corpus::Reject;
    }
    // 重复次数过大
    if contains_large_repetition(&ast, 16) {
        return Corpus::Reject;
    }

    // 包含字符 '&'
    if pattern_str.contains('&') {
        return Corpus::Reject;
    }

    // Perl 类
    if
        pattern_str.contains("\\d") ||
        pattern_str.contains("\\D") ||
        pattern_str.contains("\\w") ||
        pattern_str.contains("\\W") ||
        pattern_str.contains("\\s") ||
        pattern_str.contains("\\S")
    {
        return Corpus::Reject;
    }

    // Unicode 属性 \p{...}
    if pattern_str.contains("\\p{") {
        return Corpus::Reject;
    }
    // 复杂嵌套字符类
    if pattern_str.contains("[[") {
        return Corpus::Reject;
    }
    match compare_libraries_safely(&REGEX_LIB_MANAGER, pattern_str, &ast) {
        Ok(()) => { Corpus::Keep }
        Err(e @ ComparisonError::MismatchFound { .. }) => {
            panic!("{}", e);
        }
        Err(ComparisonError::CompilationFailed(_)) => { Corpus::Reject }
        // 没找到基准库
        Err(ComparisonError::NoBaselineFound) => {
            eprintln!("[WARN] No baseline found for pattern: {:?}", pattern_str);
            Corpus::Keep
        }
    }
});
