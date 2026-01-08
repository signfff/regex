#![no_main]
use libfuzzer_sys::{ fuzz_mutator, fuzz_target };
use regex_fuzz::diff::*;
use regex_fuzz::eqs::generate_equivalent_patterns;
use regex_syntax::ast::parse::Parser;
use std::env;

/// 将错误信息追加写入到 fuzz_failures.log 文件中
/// 如果文件写入失败，则回退到标准错误输出
fn log_failure(args: impl std::fmt::Display, errorType: String) {
    use std::fs::OpenOptions;
    use std::io::Write;
    let file_result = match errorType.as_str() {
        "DifferentialMismatch" => {
            let log_path = env
                ::var("FUZZ_DIFF_LOG")
                .expect("环境变量 FUZZ_DIFF_LOG 未设置，无法继续 fuzzing");
            OpenOptions::new().create(true).append(true).open(log_path)
        }
        "MetamorphicMismatch" => {
            let log_path = env
                ::var("FUZZ_META_LOG")
                .expect("环境变量 FUZZ_META_LOG 未设置，无法继续 fuzzing");
            OpenOptions::new().create(true).append(true).open(log_path)
        }
        "EgraphMismatch" => {
            let log_path = env
                ::var("FUZZ_META_LOG")
                .expect("环境变量 FUZZ_META_LOG 未设置，无法继续 fuzzing");
            OpenOptions::new().create(true).append(true).open(log_path)
        }
        "CompilerNotFound" => {
            let log_path = env
                ::var("FUZZ_META_LOG")
                .expect("环境变量 FUZZ_META_LOG 未设置，无法继续 fuzzing");
            OpenOptions::new().create(true).append(true).open(log_path)
        }
        _ => panic!("Unknown log type: {}", errorType),
    };

    match file_result {
        Ok(mut file) => {
            if let Err(io_err) = writeln!(file, "{}", args) {
                eprintln!("Failed to write to log file: {}; Original error: {}", io_err, args);
            }
        }
        Err(io_err) => {
            eprintln!("Failed to open log file: {}; Original error: {}", io_err, args);
        }
    }
}
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
            //  regex-lite在Unicode语义下和regex表现不同，过滤掉可以匹配Unicode字符的部分
            // TODO: 考虑显式关闭Unicode，例如r"(?-u)\d" r"(?-u)\w" r"(?-u)\s" 待讨论
            // let classes = ["\\d", "\\w", "\\s", "[a-z]", "[0-9]", ".", "[^a]"];
            let classes = ["[a-z]", "[0-9]"];

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
            // TODO: 过滤flag
            // let flags = ["(?i)", "(?m)", "(?s)", "(?x)"];
            // let flag = flags[(_seed as usize) % flags.len()];
            // if pattern.len() < max_size - flag.len() {
            //     pattern.insert_str(0, flag);
            // }
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
            // TODO: 根据差分测试结果考虑是否过滤
            let unicode_classes = ["\\p{L}", "\\p{N}", "\\p{P}", "\\p{Greek}"];
            let class = unicode_classes[(_seed as usize) % unicode_classes.len()];
            if pattern.len() < max_size - class.len() {
                let pos = if pattern.is_empty() { 0 } else { (_seed as usize) % pattern.len() };
                pattern.insert_str(pos, class);
            }
        }
        8 => {
            // FIXME:rust正则引擎不支持反向引用，因为反向引用需要回溯，无法保证线性时间复杂度
            // if !pattern.is_empty() && pattern.contains('(') {
            //     let backrefs = ["\\1", "\\2", "\\3"];
            //     let backref = backrefs[(_seed as usize) % backrefs.len()];
            //     let pos = (_seed as usize) % pattern.len();
            //     pattern.insert_str(pos, backref);
            // }
        }
        9 => {
            // FIXME:rust正则引擎不支持look-around,look-ahead,look-behind，因为性能要求限制
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
            // "[\\w&&[^\\d]]包括Unicode字符
            // let classes = ["[a-z&&[^aeiou]]", "[\\w&&[^\\d]]", "[a-z&&[^xyz]]"];
            let classes = ["[a-z&&[^aeiou]]", "[a-z&&[^xyz]]"];
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

fuzz_target!(|data: &[u8]| {
    // Convert input data to pattern
    let pattern = match String::from_utf8(data.to_vec()) {
        Ok(pat) => pat,
        Err(_) => {
            return;
        } // Invalid UTF-8, skip this input
    };

    // Convert pattern to ast
    let ast = match Parser::new().parse(&pattern) {
        Ok(ast) => ast,
        Err(_) => {
            return;
        } // Invalid pattern, skip this input
    };

    // 1. Differential Testing
    // Check if the pattern behaves consistently across different regex libraries
    // return Err if any inconsistency is found
    let manager = RegexLibManager::new();
    if let Err(e) = validate_pattern(&manager, &pattern, &ast) {
        match e {
            | ComparisonError::PreCheckFailed { .. }
            | ComparisonError::TestStringsGenerationFailed { .. } => {
                return; // Skip patterns that fail pre-checks or test string generation
            }
            ComparisonError::DifferentialMismatch { .. } => {
                log_failure(
                    format_args!("Differential testing failed, {}", e),
                    "DifferentialMismatch".to_string()
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
                    "CompilerNotFound".to_string()
                );
            }
            ComparisonError::EgraphPreCheckFailed { .. } => {
                log_failure(
                    format_args!("Egraph preCheck failed, {}", e),
                    "EgraphPreCheckFailed".to_string()
                );
            }
            ComparisonError::EgraphMismatch { .. } => {
                log_failure(format_args!("Egraph mismatch, {}", e), "EgraphMismatch".to_string());
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
                "MetamorphicMismatch".to_string()
            );
        }
    }
});
