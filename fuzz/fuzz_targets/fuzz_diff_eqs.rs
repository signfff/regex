#![no_main]
use libfuzzer_sys::{fuzz_mutator, fuzz_target};
use regex_fuzz::diff::*;
use regex_fuzz::eqs::generate_equivalent_patterns;
use regex_syntax::ast::parse::Parser;
use regex_syntax::ast::{Ast, ClassSet, ClassSetItem, Flag, Flags, GroupKind};
use std::env;
use libc;
use std::sync::Once;

static START: Once = Once::new();
static mut SHOULD_FLUSH: bool = false;

extern "C" {
    fn __llvm_profile_write_file() -> i32;
}

unsafe extern "C" fn handle_sigusr1(_sig: i32) {
    SHOULD_FLUSH = true;
}

fn setup_signal_handler() {
    unsafe {
        libc::signal(libc::SIGUSR1, handle_sigusr1 as libc::sighandler_t);
    }
}
/// 将错误信息追加写入到 fuzz_failures.log 文件中
/// 如果文件写入失败，则回退到标准错误输出
fn log_failure(args: impl std::fmt::Display, error_type: String) {
    use std::env;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process;

    // 1. 获取当前进程 ID (PID)
    let pid = process::id();

    // 2. 定义一个辅助闭包来处理路径生成
    let get_log_path = |env_var: &str| -> PathBuf {
        let path_str = env::var(env_var)
            .unwrap_or_else(|_| panic!("环境变量 {} 未设置，无法继续 fuzzing", env_var));
        
        let mut path = PathBuf::from(path_str);
        
        // 获取原有的文件名 stem (不带扩展名) 和 extension (扩展名)
        let stem = path.file_stem().unwrap_or_default().to_string_lossy();
        let extension = path.extension().unwrap_or_default().to_string_lossy();

        // 构造新文件名：name_PID.log
        let new_name = if extension.is_empty() {
            format!("{}_{}.log", stem, pid)
        } else {
            format!("{}_{}.{}", stem, pid, extension)
        };

        path.set_file_name(new_name);
        path
    };

    // 3. 根据错误类型选择日志文件
    let log_path = match error_type.as_str() {
        "DifferentialMismatch" => get_log_path("FUZZ_DIFF_LOG"),
        "MetamorphicMismatch" | "EgraphMismatch" | "CompilerNotFound" | "EgraphPreCheckFailed" => {
            get_log_path("FUZZ_META_LOG")
        }
        _ => panic!("Unknown log type: {}", error_type),
    };

    // 4. 写入日志
    // 注意：OpenOptions 每次都会打开文件，对于错误日志这种低频操作是可以接受的
    match OpenOptions::new().create(true).append(true).open(&log_path) {
        Ok(mut file) => {
            if let Err(io_err) = writeln!(file, "{}", args) {
                eprintln!(
                    "Failed to write to log file: {:?}; Original error: {}",
                    log_path, args // 打印路径方便调试
                );
                eprintln!("IO Error: {}", io_err);
            }
        }
        Err(io_err) => {
            eprintln!(
                "Failed to open log file: {:?}; Original error: {}",
                log_path, args
            );
            eprintln!("IO Error: {}", io_err);
        }
    }
}
fn chars_byte_len(chars: &[char]) -> usize {
    chars.iter().map(|c| c.len_utf8()).sum()
}

fn truncate_to_max_bytes(s: &mut String, max_size: usize) {
    if max_size == 0 {
        s.clear();
        return;
    }
    if s.len() <= max_size {
        return;
    }
    let mut cut = 0;
    for (i, ch) in s.char_indices() {
        let next = i + ch.len_utf8();
        if next > max_size {
            break;
        }
        cut = next;
    }
    s.truncate(cut);
}

#[derive(Clone, Copy)]
struct FlagState {
    unicode: bool,
}

fn apply_flags(state: &mut FlagState, flags: &Flags) {
    if let Some(u) = flags.flag_state(Flag::Unicode) {
        state.unicode = u;
    }
}

#[allow(dead_code)]
/// 判断 pattern 中是否存在可能匹配 Unicode 字符或 Unicode 属性的部分。
/// 包括但不限于：\w \d \s \p 及包含非 ASCII 字符的字面量/范围。
fn has_unicode(pattern: &str) -> bool {
    let ast = match Parser::new().parse(pattern) {
        Ok(ast) => ast,
        Err(_) => return false,
    };
    let mut state = FlagState { unicode: true };
    has_unicode_ast(&ast, &mut state)
}

fn has_unicode_ast(ast: &Ast, state: &mut FlagState) -> bool {
    match ast {
        Ast::Empty(_) | Ast::Assertion(_) => false,
        Ast::Flags(set_flags) => {
            apply_flags(state, &set_flags.flags);
            false
        }
        Ast::Literal(lit) => lit.c as u32 > 0x7f,
        Ast::Dot(_) => state.unicode,
        Ast::ClassUnicode(_) => true,
        Ast::ClassPerl(_) => state.unicode,
        Ast::ClassBracketed(bracketed) => {
            has_unicode_class_set(&bracketed.kind, *state)
        }
        Ast::Repetition(rep) => {
            let mut inner = *state;
            has_unicode_ast(&rep.ast, &mut inner)
        }
        Ast::Group(g) => {
            let mut inner = *state;
            if let GroupKind::NonCapturing(ref flags) = g.kind {
                apply_flags(&mut inner, flags);
            }
            has_unicode_ast(&g.ast, &mut inner)
        }
        Ast::Alternation(alt) => {
            for a in &alt.asts {
                let mut branch = *state;
                if has_unicode_ast(a, &mut branch) {
                    return true;
                }
            }
            false
        }
        Ast::Concat(concat) => {
            for a in &concat.asts {
                if has_unicode_ast(a, state) {
                    return true;
                }
            }
            false
        }
    }
}

fn has_unicode_class_set(set: &ClassSet, state: FlagState) -> bool {
    match set {
        ClassSet::Item(item) => has_unicode_class_set_item(item, state),
        ClassSet::BinaryOp(bin) => {
            has_unicode_class_set(&bin.lhs, state)
                || has_unicode_class_set(&bin.rhs, state)
        }
    }
}

fn has_unicode_class_set_item(item: &ClassSetItem, state: FlagState) -> bool {
    match item {
        ClassSetItem::Empty(_) => false,
        ClassSetItem::Literal(lit) => lit.c as u32 > 0x7f,
        ClassSetItem::Range(range) => {
            range.start.c as u32 > 0x7f || range.end.c as u32 > 0x7f
        }
        ClassSetItem::Ascii(_) => false,
        ClassSetItem::Unicode(_) => true,
        ClassSetItem::Perl(_) => state.unicode,
        ClassSetItem::Bracketed(bracket) => {
            has_unicode_class_set(&bracket.kind, state)
        }
        ClassSetItem::Union(union) => union
            .items
            .iter()
            .any(|it| has_unicode_class_set_item(it, state)),
    }
}

fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
    if size == 0 || max_size == 0 {
        return 0;
    }

    let pattern = String::from_utf8_lossy(&data[..size]).into_owned();
    let mut chars: Vec<char> = pattern.chars().collect();
    let mutation_type = seed % 17;

    match mutation_type {
        0 => {
            if !chars.is_empty() {
                let pos = (seed as usize) % chars.len();
                let quantifiers =
                    ["?", "{2,5}", "{1,3}", "{0,1}", "{1,}", "{2}", "{0,3}"];
                let q = quantifiers[(seed as usize) % quantifiers.len()];
                let cur_bytes = chars_byte_len(&chars);
                if cur_bytes + q.len() <= max_size {
                    chars.splice(pos..pos, q.chars());
                }
            }
        }
        1 => {
            // 现在不做unicode过滤
            let classes = ["\\d", "\\w", "\\s", "[a-z]", "[0-9]", ".", "[^a]"];
            // let classes = ["[a-z]", "[0-9]"];

            let class = classes[(seed as usize) % classes.len()];
            let cur_bytes = chars_byte_len(&chars);
            if cur_bytes + class.len() <= max_size {
                let pos = if chars.is_empty() {
                    0
                } else {
                    (seed as usize) % chars.len()
                };
                chars.splice(pos..pos, class.chars());
            }
        }
        2 => {
            let cur_bytes = chars_byte_len(&chars);
            if !chars.is_empty() && cur_bytes + 2 <= max_size {
                let pos = (seed as usize) % chars.len();
                chars.insert(pos, '|');
                chars.insert(pos + 1, 'a');
            }
        }
        3 => {
            let cur_bytes = chars_byte_len(&chars);
            if !chars.is_empty() && cur_bytes + 2 <= max_size {
                let pos = (seed as usize) % chars.len();
                chars.insert(pos, '(');
                let insert_pos = (pos + 2).min(chars.len());
                chars.insert(insert_pos, ')');
            }
        }
        4 => {
            let anchors = ["^", "$", "\\b", "\\B"];
            let anchor = anchors[(seed as usize) % anchors.len()];
            let cur_bytes = chars_byte_len(&chars);
            if cur_bytes + anchor.len() <= max_size {
                if seed % 2 == 0 {
                    chars.splice(0..0, anchor.chars());
                } else {
                    chars.extend(anchor.chars());
                }
            }
        }
        5 => {
            // FIXME: flag
            // let flags = ["(?i)", "(?m)", "(?s)", "(?x)"];
            // let flag = flags[(_seed as usize) % flags.len()];
            // if pattern.len() < max_size - flag.len() {
            //     pattern.insert_str(0, flag);
            // }
        }
        6 => {
            if !chars.is_empty() {
                let pos = (seed as usize) % chars.len();
                if let Some(&ch) = chars.get(pos) {
                    let cur_bytes = chars_byte_len(&chars);
                    if ".+*?^${}[]|()\\".contains(ch)
                        && cur_bytes + 1 <= max_size
                    {
                        chars.insert(pos, '\\');
                    }
                }
            }
        }
        7 => {
            let unicode_classes = ["\\p{L}", "\\p{N}", "\\p{P}", "\\p{Greek}"];
            let class = unicode_classes[(seed as usize) % unicode_classes.len()];
            let cur_bytes = chars_byte_len(&chars);
            if cur_bytes + class.len() <= max_size {
                let pos = if chars.is_empty() {
                    0
                } else {
                    (seed as usize) % chars.len()
                };
                chars.splice(pos..pos, class.chars());
            }
        }
        8 => {
            // FIXME:反向引用
            // if !pattern.is_empty() && pattern.contains('(') {
            //     let backrefs = ["\\1", "\\2", "\\3"];
            //     let backref = backrefs[(_seed as usize) % backrefs.len()];
            //     let pos = (_seed as usize) % pattern.len();
            //     pattern.insert_str(pos, backref);
            // }
        }
        9 => {
            // FIXME:look-around,look-ahead,look-behind
            // let assertions = ["(?=\\w)", "(?!\\d)", "(?<=\\s)", "(?<!\\W)"];
            // let assertion = assertions[(_seed as usize) % assertions.len()];
            // if pattern.len() < max_size - assertion.len() {
            //     let pos = if pattern.is_empty() {
            //         0
            //     } else {
            //         (_seed as usize) % pattern.len()
            //     };
            //     pattern.insert_str(pos, assertion);
            // }
        }
        10 => {
            let cur_bytes = chars_byte_len(&chars);
            if !chars.is_empty() && cur_bytes + 4 <= max_size {
                let pos = (seed as usize) % chars.len();
                chars.splice(pos..pos, "(?:".chars());
                let insert_pos = (pos + 3).min(chars.len());
                chars.insert(insert_pos, ')');
            }
        }
        11 => {
            // TODO:包含&&容易在regex-automata中状态爆炸导致oom或者timeout，待优化处理
            // let classes = ["[a-z&&[^aeiou]]", "[a-z&&[^xyz]]", "[\\w&&[^\\d]]"];
            let classes = ["[b-df-hj-np-tv-z]", "[a-w]", "[A-Za-z_]"];
            let class = classes[(seed as usize) % classes.len()];
            let cur_bytes = chars_byte_len(&chars);
            if cur_bytes + class.len() <= max_size {
                let pos = if chars.is_empty() {
                    0
                } else {
                    (seed as usize) % chars.len()
                };
                chars.splice(pos..pos, class.chars());
            }
        }
        12 => {
            if !chars.is_empty() {
                let pos = (seed as usize) % chars.len();
                chars.remove(pos);
            }
        }
        13 => {
            if !chars.is_empty() {
                let start = (seed as usize) % chars.len();
                let max_len = (chars.len() - start).max(1);
                let len = (((seed >> 8) as usize) % max_len) + 1;
                let end = (start + len).min(chars.len());
                chars.drain(start..end);
            }
        }
        14 => {
            let mut cur_bytes = chars_byte_len(&chars);
            if !chars.is_empty() && cur_bytes < max_size {
                let start = (seed as usize) % chars.len();
                let max_len = (chars.len() - start).max(1);
                let len = (((seed >> 8) as usize) % max_len) + 1;
                let end = (start + len).min(chars.len());

                let sub_chars: Vec<char> = chars[start..end].to_vec();
                let sub_bytes = chars_byte_len(&sub_chars);
                let repeat_count = ((seed >> 16) % 3) + 1;

                let mut insert_at = end;
                for _ in 0..repeat_count {
                    if cur_bytes + sub_bytes <= max_size {
                        chars.splice(insert_at..insert_at, sub_chars.iter().cloned());
                        insert_at += sub_chars.len();
                        cur_bytes += sub_bytes;
                    } else {
                        break;
                    }
                }
            }
        }
        _ => {
            if !chars.is_empty() {
                let pos = (seed as usize) % chars.len();
                let replacements = [
                    'a', '1', '.', '*', '|', '(', ')', '[', ']', '\\', '{',
                    '}', '-', '^', '$',
                ];
                let replacement =
                    replacements[(seed as usize) % replacements.len()];
                chars[pos] = replacement;
            }
        }
    }

    let mut pattern: String = chars.iter().collect();
    truncate_to_max_bytes(&mut pattern, max_size);
    let bytes = pattern.as_bytes();
    let copy_len = std::cmp::min(bytes.len(), max_size);
    data[..copy_len].copy_from_slice(&bytes[..copy_len]);
    copy_len
});

fuzz_target!(|data: &[u8]| {
    START.call_once(|| {
        setup_signal_handler();
    });

    if unsafe { SHOULD_FLUSH } {
        unsafe {
            __llvm_profile_write_file();
            SHOULD_FLUSH = false;
        }
    }
    // Convert input data to pattern
    let pattern = match String::from_utf8(data.to_vec()) {
        Ok(pat) => pat,
        Err(_) => {
            return;
        } // Invalid UTF-8, skip this input
    };

    if contains_unsupported_perl(&pattern) {
        // println!("contains_unsupported_perl: {}", pattern);
        return;
    }

    // Convert pattern to ast
    let ast = match Parser::new().parse(&pattern) {
        Ok(ast) => ast,
        Err(_) => {
            return;
        } // Invalid pattern, skip this input
    };
    let hasUnicode=has_unicode(&pattern);
    // 1. Differential Testing
    // Check if the pattern behaves consistently across different regex libraries
    // return Err if any inconsistency is found
    let manager = RegexLibManager::new();
    if let Err(e) = validate_pattern(&manager, &pattern, &ast, hasUnicode) {
        match e {
            ComparisonError::PreCheckFailed { .. }
            | ComparisonError::TestStringsGenerationFailed { .. } => {
                return; // Skip patterns that fail pre-checks or test string generation
            }
            ComparisonError::DifferentialMismatch { .. } => {
                log_failure(
                    format_args!("Differential testing failed, {}", e),
                    "DifferentialMismatch".to_string(),
                );
            }
            _ => {
                panic!("Unexpected error during differential testing: {}", e);
            }
        }
    }

    // 2. Metamorphic Testing
    // Generate equivalent patterns and verify they behave the same as the original
    // Limit: 3 iterations, min 1 pattern, max 10 patterns to keep fuzzing fast
    let eq_patterns = match generate_equivalent_patterns(&pattern, 3, 1, 10) {
        Ok(pats) => pats,
        Err(_) => {
            return;
        } // No equivalent patterns found or error, skip metamorphic test
    };

    if let Err(e) = validate_eq_patterns(&manager, &pattern, &eq_patterns) {
        match e {
            ComparisonError::TestStringsGenerationFailed { .. } => {
                return;
            }
            ComparisonError::CompilerNotFound { .. } => {
                log_failure(
                    format_args!("CompilerNotFound, {}", e),
                    "CompilerNotFound".to_string(),
                );
            }
            ComparisonError::EgraphPreCheckFailed { .. } => {
                log_failure(
                    format_args!("Egraph preCheck failed, {}", e),
                    "EgraphPreCheckFailed".to_string(),
                );
            }
            ComparisonError::EgraphMismatch { .. } => {
                log_failure(
                    format_args!("Egraph mismatch, {}", e),
                    "EgraphMismatch".to_string(),
                );
            }
            _ => {
                panic!("Unreachable error type during Egraph check: {}", e)
            }
        }
    }
    // Test each equivalent pattern on different regex libs
    for eq_pat in eq_patterns {
        if let Err(e) = validate_regexLib(&manager, &eq_pat) {
            log_failure(
                format_args!("Metamorphic testing failed, {}", e),
                "MetamorphicMismatch".to_string(),
            );
        }
    }
});
