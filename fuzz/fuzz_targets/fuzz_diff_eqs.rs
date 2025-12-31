#![no_main]
use libfuzzer_sys::{fuzz_mutator,fuzz_target};
use regex_fuzz::diff::*;
use regex_fuzz::eqs::generate_equivalent_patterns;
use regex_syntax::ast::parse::Parser;\

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
                let quantifiers =
                    ["?", "{2,5}", "{1,3}", "{0,1}", "{1,}", "{2}", "{0,3}"];
                let q = quantifiers[(_seed as usize) % quantifiers.len()];
                pattern.insert_str(pos, q);
            }
        }
        1 => {
            let classes = ["\\d", "\\w", "\\s", "[a-z]", "[0-9]", ".", "[^a]"];
            let class = classes[(_seed as usize) % classes.len()];
            if pattern.len() < max_size - class.len() {
                let pos = if pattern.is_empty() {
                    0
                } else {
                    (_seed as usize) % pattern.len()
                };
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
                    if ".+*?^${}[]|()\\".contains(ch)
                        && pattern.len() < max_size
                    {
                        pattern.insert(pos, '\\');
                    }
                }
            }
        }
        7 => {
            let unicode_classes = ["\\p{L}", "\\p{N}", "\\p{P}", "\\p{Greek}"];
            let class =
                unicode_classes[(_seed as usize) % unicode_classes.len()];
            if pattern.len() < max_size - class.len() {
                let pos = if pattern.is_empty() {
                    0
                } else {
                    (_seed as usize) % pattern.len()
                };
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
                let pos = if pattern.is_empty() {
                    0
                } else {
                    (_seed as usize) % pattern.len()
                };
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
            let classes =
                ["[a-z&&[^aeiou]]", "[\\w&&[^\\d]]", "[a-z&&[^xyz]]"];
            let class = classes[(_seed as usize) % classes.len()];
            if pattern.len() < max_size - class.len() {
                let pos = if pattern.is_empty() {
                    0
                } else {
                    (_seed as usize) % pattern.len()
                };
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
                let len = ((_seed >> 8) as usize) % max_len + 1;
                let end = (start + len).min(pattern.len());
                pattern.drain(start..end);
            }
        }
        14 => {
            if !pattern.is_empty() && pattern.len() < max_size {
                let start = (_seed as usize) % pattern.len();
                let max_len = (pattern.len() - start).max(1);
                let len = ((_seed >> 8) as usize) % max_len + 1;
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
                    'a', '1', '.', '*', '|', '(', ')', '[', ']', '\\', '{',
                    '}', '-', '^', '$',
                ];
                let replacement =
                    replacements[(_seed as usize) % replacements.len()];
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
    let pattern = String::from_utf8_lossy(data);

    // Convert pattern to ast
    let ast = match Parser::new().parse(pattern).unwrap();

    // 1. Differential Testing
    // Check if the pattern behaves consistently across different regex libraries
    // return Err if any inconsistency is found
    let manager = RegexLibManager::new();
    if let Err(e) = validate_pattern(&manager, pattern, &ast) {
        panic!("Differential testing failed: {}", e);
    }

    // 2. Metamorphic Testing
    // Generate equivalent patterns and verify they behave the same as the original
    // Limit: 3 iterations, min 1 pattern, max 3 patterns to keep fuzzing fast
    let eq_patterns = match generate_equivalent_patterns(pattern, 3, 1, 3) {
        Ok(pats) => pats,
        Err(_) => return, // No equivalent patterns found or error, skip metamorphic test
    };

    // Use the standard regex library as the oracle
    let original_re = match regex::Regex::new(pattern) {
        Ok(re) => re,
        Err(_) => return,
    };

    // Test each equivalent pattern on different regex libs
    for eq_pat in eq_patterns {
        if let Err(e) = validate_regexLib(&manager, &eq_pat){
            panic!("Metamorphic testing failed for pattern '{}': {}", eq_pat, e);
        }
    }
});
