#![no_main]
use libfuzzer_sys::fuzz_target;
use regex_fuzz::diff::{RegexLibManager, compare_libraries_safely, gen_multiple_accepted_strings};
use regex_fuzz::eqs::generate_equivalent_patterns;
use regex_syntax::ast::parse::Parser;

fuzz_target!(|data: &[u8]| {
    // Convert input data to a string pattern
    let pattern = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return,
    };
    
    // Parse AST to check validity
    let ast = match Parser::new().parse(pattern) {
        Ok(ast) => ast,
        Err(_) => return, // Invalid pattern, ignore
    };

    // 1. Differential Testing
    // Check if the pattern behaves consistently across different regex libraries
    let manager = RegexLibManager::new();
    if let Err(e) = compare_libraries_safely(&manager, pattern, &ast) {
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

    // Generate test strings accepted by the original pattern
    let test_strings = gen_multiple_accepted_strings(pattern, 20);
    
    for eq_pat in eq_patterns {
        let eq_re = match regex::Regex::new(&eq_pat) {
            Ok(re) => re,
            Err(_) => continue,
        };

        // Forward check: Original's accepted strings should be accepted by Equivalent
        for s in &test_strings {
            let original_match = original_re.is_match(s);
            let eq_match = eq_re.is_match(s);
            
            if original_match != eq_match {
                 panic!(
                    "Metamorphic testing failed!\nOriginal: {}\nEquivalent: {}\nInput: {:?}\nOriginal match: {}\nEquivalent match: {}",
                    pattern, eq_pat, s, original_match, eq_match
                );
            }
        }
        
        // Reverse check: Equivalent's accepted strings should be accepted by Original
        let eq_test_strings = gen_multiple_accepted_strings(&eq_pat, 10);
        for s in &eq_test_strings {
             let original_match = original_re.is_match(s);
             let eq_match = eq_re.is_match(s);
             
             if original_match != eq_match {
                 panic!(
                    "Metamorphic testing failed (reverse)!\nOriginal: {}\nEquivalent: {}\nInput: {:?}\nOriginal match: {}\nEquivalent match: {}",
                    pattern, eq_pat, s, original_match, eq_match
                );
            }
        }
    }
});
