#![allow(deprecated)]
#![allow(unused_variables)]
use egg::{define_language, EGraph, Id, RecExpr, Rewrite, Runner, rewrite, Language};
use regex_syntax::ast::{parse::Parser, Ast};
use std::hash::{Hash};

// Define a language for regex expressions that can be used with egg
define_language! {
    pub enum RegexLang {
        // Literals
        "lit" = Literal([Id; 1]),
        
        // Concatenation
        "concat" = Concat(Box<[Id]>),
        
        // Alternation
        "|" = Alternation([Id; 2]),
        
        // Repetition/Quantifiers
        "*" = Star([Id; 1]),
        "+" = Plus([Id; 1]),
        "?" = Question([Id; 1]),
        "repeat" = Repeat([Id; 3]), // expr, min, max
        
        // Character classes
        "class" = Class([Id; 1]),
        "dot" = Dot,
        ClassStr(String),  // Store bracketed class as string like "[a-z]", "[0-9]", etc.
        
        // Groups
        "group" = Group([Id; 1]),
        
        // Anchors
        "^" = StartLine,
        "$" = EndLine,
        "\\b" = WordBoundary,
        "\\B" = NotWordBoundary,
        
        // Flags
        FlagsStr(String),  // Store flags as string like "(?i)", "(?m)", etc.
        
        // Constants (for repeat bounds, character values)
        Num(i32),
        Char(char),
        
        // Empty/epsilon
        "empty" = Empty,
    }
}

/// Converts a regex pattern string into a RecExpr representation.
///
/// # Arguments
/// * `pattern` - A regex pattern string (e.g., "a+b*", "[0-9]+")
///
/// # Returns
/// * `Result<RecExpr<RegexLang>, String>` - A RecExpr on success, or an error message
///
/// # Example
/// ```
/// let expr = pattern_to_expr("a+b*").unwrap();
/// ```
pub fn pattern_to_expr(pattern: &str) -> Result<RecExpr<RegexLang>, String> {
    // Parse the regex pattern into an AST
    let ast = Parser::new()
        .parse(pattern)
        .map_err(|e| format!("Failed to parse regex pattern: {}", e))?;
    
    // Convert AST to RecExpr
    let expr = ast_to_recexpr(&ast)?;
    
    Ok(expr)
}

/// Converts a regex pattern string into an e-graph representation using egg.
///
/// # Arguments
/// * `pattern` - A regex pattern string (e.g., "a+b*", "[0-9]+")
///
/// # Returns
/// * `Result<EGraph<RegexLang, ()>, String>` - An e-graph on success, or an error message
///
/// # Example
/// ```
/// let (egraph, root) = pattern_to_egraph("a+b*").unwrap();
/// ```
pub fn pattern_to_egraph(pattern: &str) -> Result<(EGraph<RegexLang, ()>, Id), String> {
    // Parse the regex pattern into an AST
    let ast = Parser::new()
        .parse(pattern)
        .map_err(|e| format!("Failed to parse regex pattern: {}", e))?;
    
    // Create a new e-graph
    let mut egraph = EGraph::default();
    
    // Convert AST to RecExpr and add to e-graph
    let expr = ast_to_recexpr(&ast)?;
    let root = egraph.add_expr(&expr);
    
    Ok((egraph, root))
}

/// Helper function to convert regex AST to a RecExpr for egg
fn ast_to_recexpr(ast: &Ast) -> Result<RecExpr<RegexLang>, String> {
    let mut expr = RecExpr::default();
    ast_to_recexpr_impl(ast, &mut expr)?;
    Ok(expr)
}

/// Recursive implementation that builds a RecExpr from a regex AST
fn ast_to_recexpr_impl(ast: &Ast, expr: &mut RecExpr<RegexLang>) -> Result<Id, String> {
    use regex_syntax::ast::*;
    
    match ast {
        // Empty pattern
        Ast::Empty(_) => {
            let id = expr.add(RegexLang::Empty);
            Ok(id)
        }
        
        // Literal characters
        Ast::Literal(lit) => {
            let char_id = expr.add(RegexLang::Char(lit.c));
            let lit_id = expr.add(RegexLang::Literal([char_id]));
            Ok(lit_id)
        }
        
        // Dot (matches any character)
        Ast::Dot(_) => {
            let id = expr.add(RegexLang::Dot);
            Ok(id)
        }
        
        // Concatenation
        Ast::Concat(concat) => {
            if concat.asts.is_empty() {
                return Ok(expr.add(RegexLang::Empty));
            }
            
            if concat.asts.len() == 1 {
                return ast_to_recexpr_impl(&concat.asts[0], expr);
            }
            
            let mut ids = Vec::new();
            for child in &concat.asts {
                let child_id = ast_to_recexpr_impl(child, expr)?;
                ids.push(child_id);
            }
            
            let concat_id = expr.add(RegexLang::Concat(ids.into_boxed_slice()));
            Ok(concat_id)
        }
        
        // Alternation
        Ast::Alternation(alt) => {
            if alt.asts.is_empty() {
                return Ok(expr.add(RegexLang::Empty));
            }
            
            if alt.asts.len() == 1 {
                return ast_to_recexpr_impl(&alt.asts[0], expr);
            }
            
            // Build nested alternations for multiple branches
            let mut result_id = ast_to_recexpr_impl(&alt.asts[0], expr)?;
            for i in 1..alt.asts.len() {
                let right_id = ast_to_recexpr_impl(&alt.asts[i], expr)?;
                result_id = expr.add(RegexLang::Alternation([result_id, right_id]));
            }
            
            Ok(result_id)
        }
        
        // Repetition (*, +, ?, {n,m})
        Ast::Repetition(rep) => {
            let child_id = ast_to_recexpr_impl(&rep.ast, expr)?;
            
            match &rep.op.kind {
                RepetitionKind::ZeroOrOne => {
                    let id = expr.add(RegexLang::Question([child_id]));
                    Ok(id)
                }
                RepetitionKind::ZeroOrMore => {
                    let id = expr.add(RegexLang::Star([child_id]));
                    Ok(id)
                }
                RepetitionKind::OneOrMore => {
                    let id = expr.add(RegexLang::Plus([child_id]));
                    Ok(id)
                }
                RepetitionKind::Range(range) => {
                    // RepetitionRange is an enum, not a struct with fields
                    match range {
                        RepetitionRange::Exactly(n) => {
                            let min_id = expr.add(RegexLang::Num(*n as i32));
                            let max_id = expr.add(RegexLang::Num(*n as i32));
                            let id = expr.add(RegexLang::Repeat([child_id, min_id, max_id]));
                            Ok(id)
                        }
                        RepetitionRange::AtLeast(n) => {
                            let min_id = expr.add(RegexLang::Num(*n as i32));
                            let max_id = expr.add(RegexLang::Num(-1)); // unbounded
                            let id = expr.add(RegexLang::Repeat([child_id, min_id, max_id]));
                            Ok(id)
                        }
                        RepetitionRange::Bounded(min, max) => {
                            let min_id = expr.add(RegexLang::Num(*min as i32));
                            let max_id = expr.add(RegexLang::Num(*max as i32));
                            let id = expr.add(RegexLang::Repeat([child_id, min_id, max_id]));
                            Ok(id)
                        }
                    }
                }
            }
        }
        
        // Groups
        Ast::Group(group) => {
            let child_id = ast_to_recexpr_impl(&group.ast, expr)?;
            let id = expr.add(RegexLang::Group([child_id]));
            Ok(id)
        }
        
        // Character classes
        Ast::ClassBracketed(class) => {
            // Convert the bracketed character class to its string representation
            // Use the Ast's Display implementation which properly formats the class
            let class_ast = Ast::ClassBracketed(class.clone());
            let class_str = format!("{}", class_ast);
            let id = expr.add(RegexLang::ClassStr(class_str));
            Ok(id)
        }

        _ => {
            panic!("Unsupported AST node: {:?}", ast);
        }
        
        // Ast::ClassPerl(perl) => {
        //     // Convert Perl character classes like \d, \w, \s to string
        //     let class_ast = Ast::ClassPerl(perl.clone());
        //     let class_str = format!("{}", class_ast);
        //     let id = expr.add(RegexLang::ClassStr(class_str));
        //     Ok(id)
        // }
        
        // Ast::ClassUnicode(unicode) => {
        //     // Convert Unicode character classes to string
        //     let class_ast = Ast::ClassUnicode(unicode.clone());
        //     let class_str = format!("{}", class_ast);
        //     let id = expr.add(RegexLang::ClassStr(class_str));
        //     Ok(id)
        // }
        
        // // Assertions/Anchors
        // Ast::Assertion(assertion) => {
        //     match assertion.kind {
        //         AssertionKind::StartLine => {
        //             let id = expr.add(RegexLang::StartLine);
        //             Ok(id)
        //         }
        //         AssertionKind::EndLine => {
        //             let id = expr.add(RegexLang::EndLine);
        //             Ok(id)
        //         }
        //         AssertionKind::WordBoundary => {
        //             let id = expr.add(RegexLang::WordBoundary);
        //             Ok(id)
        //         }
        //         AssertionKind::NotWordBoundary => {
        //             let id = expr.add(RegexLang::NotWordBoundary);
        //             Ok(id)
        //         }
        //         _ => {
        //             // For other assertion types, use empty as fallback
        //             let id = expr.add(RegexLang::Empty);
        //             Ok(id)
        //         }
        //     }
        // }
        
        // // Flags - represent them as flag strings
        // Ast::Flags(flags) => {
        //     // Convert flags to their string representation
        //     // Flags like (?i), (?m), (?s), etc.
        //     let flags_ast = Ast::Flags(flags.clone());
        //     let flags_str = format!("{}", flags_ast);
        //     let id = expr.add(RegexLang::FlagsStr(flags_str));
        //     Ok(id)
        // }
    }
}

/// Creates a set of rewrite rules for regex optimization
fn make_rewrite_rules() -> Vec<Rewrite<RegexLang, ()>> {
    let rules = vec![
        // Algebraic identities for alternation
        rewrite!("alt-idempotent"; "(| ?x ?x)" => "?x"),
        rewrite!("alt-commutative"; "(| ?x ?y)" => "(| ?y ?x)"),
        rewrite!("alt-associative"; "(| ?x (| ?y ?z))" => "(| (| ?x ?y) ?z)"),
        
        // Star identities
        rewrite!("star-star"; "(* (* ?x))" => "(* ?x)"),
        rewrite!("star-empty"; "(* empty)" => "empty"),
        
        // // Plus identities
        // rewrite!("plus-to-star"; "(+ ?x)" => "(concat ?x (* ?x))"),
        // rewrite!("star-to-plus-or-empty"; "(* ?x)" => "(| (+ ?x) empty)"),
        
        // Question identities - commented out to preserve ? structure
        rewrite!("question-to-alt"; "(? ?x)" => "(| ?x empty)"),
        rewrite!("question-question"; "(? (? ?x))" => "(? ?x)"),
        
        // Distribution laws
        rewrite!("concat-dist-alt-left"; "(concat ?x (| ?y ?z))" => "(| (concat ?x ?y) (concat ?x ?z))"),
        rewrite!("concat-dist-alt-right"; "(concat (| ?x ?y) ?z)" => "(| (concat ?x ?z) (concat ?y ?z))"),
        
        // Star absorption
        rewrite!("plus-star"; "(* (+ ?x))" => "(* ?x)"),
        rewrite!("question-star"; "(* (? ?x))" => "(* ?x)"),
        rewrite!("question-plus"; "(+ (? ?x))" => "(* ?x)"),
        
        // Concatenation associativity (simplified for binary case)
        rewrite!("concat-assoc"; "(concat (concat ?x ?y) ?z)" => "(concat ?x (concat ?y ?z))"),
        
        // Repetition simplifications
        rewrite!("star-plus"; "(concat ?x (* ?x))" => "(+ ?x)"),
        rewrite!("star-absorb-concat"; "(concat (* ?x) (* ?x))" => "(* ?x)"),
        
        // Plus identities
        rewrite!("plus-plus"; "(+ (+ ?x))" => "(+ ?x)"),
        rewrite!("plus-question"; "(? (+ ?x))" => "(* ?x)"),
        
        // Nested quantifier simplifications
        rewrite!("star-question"; "(? (* ?x))" => "(* ?x)"),
        
        // Alternation simplifications
        rewrite!("alt-assoc-right"; "(| (| ?x ?y) ?z)" => "(| ?x (| ?y ?z))"),
        
        // Double negation-like: optional of optional is optional
        rewrite!("question-plus-star"; "(+ (+ ?x))" => "(+ ?x)"),
        
        // Star is idempotent with plus
        rewrite!("star-plus-absorb"; "(* (+ ?x))" => "(* ?x)"),
        
        // Simplified question absorption
        rewrite!("plus-optional"; "(concat (? ?x) (* ?x))" => "(* ?x)"),
        
        // Empty group elimination
        rewrite!("group-star"; "(group (* ?x))" => "(* (group ?x))"),
        rewrite!("group-plus"; "(group (+ ?x))" => "(+ (group ?x))"),
        rewrite!("group-question"; "(group (? ?x))" => "(? (group ?x))"),
    ];
    
    rules
}

/// Performs rewrite operations on a regex expression to find equivalent patterns.
///
/// This function creates an e-graph from the expression, applies rewrite rules,
/// and performs equality saturation to discover all equivalent representations.
///
/// # Arguments
/// * `expr` - A RecExpr representing the regex pattern
/// * `iter_limit` - Maximum number of iterations for equality saturation (default: 11)
///
/// # Returns
/// * A tuple containing the final e-graph and the root e-class ID
///
/// # Example
/// ```
/// let expr = pattern_to_expr("a+").unwrap();
/// let (egraph, root) = perform_rewrites(&expr, 10);
/// println!("Found {} equivalence classes", egraph.number_of_classes());
/// ```
pub fn perform_rewrites(expr: &RecExpr<RegexLang>, iter_limit: usize) -> (EGraph<RegexLang, ()>, Id) {
    let rules = make_rewrite_rules();
    
    
    // eprintln!("\n╔════════════════════════════════════════════════════════════════╗");
    // eprintln!("║         STARTING REWRITE PROCESS                               ║");
    // eprintln!("╚════════════════════════════════════════════════════════════════╝");
    // eprintln!("Initial e-graph state:");
    // eprintln!("  - Iteration limit: {}", iter_limit);
    // eprintln!("  - Number of rewrite rules: {}\n", rules.len());
    
    // Run equality saturation with hook to show each step
    let runner = Runner::default()
        .with_explanations_enabled()
        .with_iter_limit(iter_limit)
        // .with_egraph(egraph.clone())
        .with_expr(expr)
        // .with_hook(|runner| {
        //     let iteration = runner.iterations.len();
        //     if iteration == 0 {
        //         return Ok(());
        //     }
        //     let report = &runner.iterations[iteration - 1];
            
        //     eprintln!("┌─────────────────────────────────────────────────────────────┐");
        //     eprintln!("│ ITERATION {} COMPLETED", iteration);
        //     eprintln!("├─────────────────────────────────────────────────────────────┤");
        //     eprintln!("│ E-graph Statistics:");
        //     eprintln!("│   • E-classes: {}", runner.egraph.number_of_classes());
        //     eprintln!("│   • E-nodes: {}", runner.egraph.total_size());
        //     eprintln!("│   • Applied rules: {}", report.applied.values().sum::<usize>());
        //     eprintln!("│   • Search time: {:.2?}", report.search_time);
        //     eprintln!("│   • Apply time: {:.2?}", report.apply_time);
        //     eprintln!("│   • Rebuild time: {:.2?}", report.rebuild_time);
        //     eprintln!("│");
            
        //     if !report.applied.is_empty() {
        //         eprintln!("│ Rules Applied This Iteration:");
        //         let mut applied_rules: Vec<_> = report.applied.iter().collect();
        //         applied_rules.sort_by_key(|(_, count)| std::cmp::Reverse(**count));
                
        //         let mut count = 0;
        //         for (rule_name, rule_count) in &applied_rules {
        //             if **rule_count > 0 {
        //                 count += 1;
        //                 if count <= 8 {  // Show top 8 rules to avoid clutter
        //                     let rule_str = rule_name.to_string();
        //                     let truncated_rule = if rule_str.len() > 25 {
        //                         format!("{}...", rule_str.chars().take(22).collect::<String>())
        //                     } else {
        //                         rule_str
        //                     };
        //                     eprintln!("│   • {:25} : {} times", truncated_rule, rule_count);
        //                 }
        //             }
        //         }
                
        //         if count > 8 {
        //             eprintln!("│   • ... and {} more rules", count - 8);
        //         }
                
        //         eprintln!("│");
        //         eprintln!("│ Step-by-step rule applications:");
        //         for (rule_name, rule_count) in applied_rules.iter().take(3) {
        //             if **rule_count > 0 {
        //                 eprintln!("│   → {} applied {} time(s)", rule_name, rule_count);
                        
        //                 // Show what this rule does
        //                 match rule_name.as_str() {
        //                     "plus-to-star" => eprintln!("│     Transforms: a+ → a(a*)"),
        //                     "star-to-plus-or-empty" => eprintln!("│     Transforms: a* → a+|ε"),
        //                     "question-to-alt" => eprintln!("│     Transforms: a? → a|ε"),
        //                     "group-elim" => eprintln!("│     Transforms: (group a) → a"),
        //                     "alt-commutative" => eprintln!("│     Transforms: a|b → b|a"),
        //                     "alt-associative" => eprintln!("│     Transforms: a|(b|c) → (a|b)|c"),
        //                     "concat-assoc" => eprintln!("│     Transforms: (ab)c → a(bc)"),
        //                     "star-star" => eprintln!("│     Transforms: (a*)* → a*"),
        //                     "plus-plus" => eprintln!("│     Transforms: (a+)+ → a+"),
        //                     "concat-dist-alt-left" => eprintln!("│     Transforms: a(b|c) → ab|ac"),
        //                     "concat-dist-alt-right" => eprintln!("│     Transforms: (a|b)c → ac|bc"),
        //                     _ => eprintln!("│     (Rule description not available)"),
        //                 }
        //             }
        //         }
        //     } else {
        //         eprintln!("│ No rules applied this iteration (saturation reached)");
        //     }
            
        //     eprintln!("└─────────────────────────────────────────────────────────────┘\n");
            
        //     Ok(())
        // })
        .run(&rules);
    
    // eprintln!("╔════════════════════════════════════════════════════════════════╗");
    // eprintln!("║         REWRITE PROCESS COMPLETED                              ║");
    // eprintln!("╚════════════════════════════════════════════════════════════════╝");
    // eprintln!("Final e-graph state:");
    // eprintln!("  - Total iterations: {}", runner.iterations.len());
    // eprintln!("  - Number of e-classes: {}", runner.egraph.number_of_classes());
    // eprintln!("  - Number of e-nodes: {}", runner.egraph.total_size());
    // eprintln!("  - Stop reason: {:?}", runner.stop_reason);
    
    let total_time_secs: f64 = runner.iterations.iter().map(|i| i.total_time).sum();
    // eprintln!("  - Total time: {:.2?}s\n", total_time_secs);

    // Get the final e-graph and root
    let final_egraph = runner.egraph;
    let final_root = runner.roots[0];
    let eclz = &final_egraph[final_root];

    // // iter node of eclz
    // eprintln!("Final root e-class ID: {:?}", final_root);
    // eprintln!("Final root e-class has {} e-nodes.", eclz.len());
    // eclz.iter().for_each(|node| {
    //     let re = node.build_recexpr(|id| final_egraph[id].nodes[0].clone());
    //     // eprintln!("  - E-node: {:?}", node);
    //     eprintln!("  - E-node pattern: '{}'", recexpr_to_pattern(&re));
    // });

    


    
    // Return the e-graph and root ID
    (final_egraph, final_root)
}

/// Extracts all unique equivalent patterns from the e-graph.
///
/// This function extracts distinct expressions from the e-graph after rewrites
/// have already been performed. It will extract patterns until it has at least
/// min_patterns unique patterns, or exhausts all possibilities.
///
/// # Arguments
/// * `egraph` - A reference to the e-graph (already rewritten)
/// * `root` - The root e-class ID of the original pattern
/// * `min_patterns` - Minimum number of unique patterns to extract
///
/// # Returns
/// * A vector of `RecExpr<RegexLang>` representing equivalent regex patterns
pub fn extract_patterns(
    egraph: &EGraph<RegexLang, ()>,
    root: Id,
    min_patterns: usize,
) -> Vec<RecExpr<RegexLang>> {
    eprintln!("Extracting patterns from root e-class: {:?}", root);
    eprintln!("Target: at least {} unique patterns", min_patterns);
    
    // Extract expressions using random selection
    let mut extracted_exprs = Vec::new();
    let mut seen_patterns = std::collections::HashSet::new();
    
    // Get all nodes in the root e-class
    let root_eclass = &egraph[root];
    let num_nodes = root_eclass.nodes.len();

    eprintln!("Root e-class has {} nodes", num_nodes);
    
    // First pass: try each node in the root e-class
    for _ in root_eclass.nodes.iter() {
        let get_enode = |id: Id| {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let nodes = &egraph[id].nodes;
            let random_index = rng.gen_range(0..nodes.len());
            nodes[random_index].clone()
        };
        
        let expr = get_enode(root).build_recexpr(get_enode);
        let pattern = recexpr_to_pattern(&expr);
        
        if seen_patterns.insert(pattern.clone()) {
            eprintln!("  [{}] Extracted unique pattern: '{}'", extracted_exprs.len(), pattern);
            extracted_exprs.push(expr);
        }
    }
    

    
    // Second pass: if we don't have enough patterns, try random sampling
    let max_attempts = min_patterns.saturating_mul(10).max(100);
    let mut attempts = 0;
    
    while extracted_exprs.len() < min_patterns && attempts < max_attempts {
        let get_enode = |id: Id| {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let nodes = &egraph[id].nodes;
            let random_index = rng.gen_range(0..nodes.len());
            nodes[random_index].clone()
        };
        
        let expr = get_enode(root).build_recexpr(get_enode);
        let pattern = recexpr_to_pattern(&expr);
        
        if seen_patterns.insert(pattern.clone()) {
            eprintln!("  [{}] Extracted unique pattern (random sampling): '{}'", extracted_exprs.len(), pattern);
            extracted_exprs.push(expr);
        }
        
        attempts += 1;
    }
    
    eprintln!("Extracted {} unique patterns after {} attempts", extracted_exprs.len(), num_nodes + attempts);
    
    extracted_exprs
}

/// Converts a RecExpr back to a regex pattern string
pub fn recexpr_to_pattern(expr: &RecExpr<RegexLang>) -> String {
    if expr.as_ref().is_empty() {
        eprintln!("Warning: Empty RecExpr passed to recexpr_to_pattern");
        return String::new();
    }
    
    let root_id = Id::from(expr.as_ref().len() - 1);
    let pattern = recexpr_to_pattern_helper(expr, root_id);
    pattern
}

fn recexpr_to_pattern_helper(expr: &RecExpr<RegexLang>, id: Id) -> String {
    let node = &expr.as_ref()[usize::from(id)];
    
    match node {
        RegexLang::Char(c) => {
            match c {
                '[' | ']' | '(' | ')' | '{' | '}' | '.' | '*' | '+' | '?' | '|' | '^' | '$' | '\\' => format!("\\{}", c),
                _ => c.to_string()
            }
        }
        RegexLang::Literal([child]) => recexpr_to_pattern_helper(expr, *child),
        RegexLang::Concat(children) => {
            children.iter()
                .map(|child| {
                    let child_node = &expr.as_ref()[usize::from(*child)];
                    let child_str = recexpr_to_pattern_helper(expr, *child);
                    if matches!(child_node, RegexLang::Alternation(_)) {
                        format!("({})", child_str)
                    } else {
                        child_str
                    }
                })
                .collect::<Vec<_>>()
                .join("")
        }
        RegexLang::Alternation([left, right]) => {
            let left_str = recexpr_to_pattern_helper(expr, *left);
            let right_str = recexpr_to_pattern_helper(expr, *right);
            
            if left_str.is_empty() && right_str.is_empty() {
                return String::new();
            }
            
            format!("{}|{}", left_str, right_str)
        }
        RegexLang::Star([child]) => {
            format!("({})*", recexpr_to_pattern_helper(expr, *child))
        }
        RegexLang::Plus([child]) => {
            format!("({})+", recexpr_to_pattern_helper(expr, *child))
        }
        RegexLang::Question([child]) => {
            format!("({})?", recexpr_to_pattern_helper(expr, *child))
        }
        RegexLang::Repeat([child, min, max]) => {
            let child_str = recexpr_to_pattern_helper(expr, *child);
            let min_val = if let RegexLang::Num(n) = &expr.as_ref()[usize::from(*min)] { *n } else { 0 };
            let max_val = if let RegexLang::Num(n) = &expr.as_ref()[usize::from(*max)] { *n } else { -1 };
            
            if max_val == -1 {
                format!("({}){{{},}}", child_str, min_val)
            } else {
                format!("({}){{{},{}}}", child_str, min_val, max_val)
            }
        }
        RegexLang::Group([child]) => {
            format!("({})", recexpr_to_pattern_helper(expr, *child))
        }
        RegexLang::Class([child]) => {
            let child_str = recexpr_to_pattern_helper(expr, *child);
            if !child_str.is_empty() {
                format!("[{}]", child_str)
            } else {
                ".".to_string()
            }
        }
        RegexLang::ClassStr(s) => {
            if s == "empty" {
                "".to_string()
            } else {
                s.clone()
            }
        }
        RegexLang::Dot => ".".to_string(),
        RegexLang::StartLine => "^".to_string(),
        RegexLang::EndLine => "$".to_string(),
        RegexLang::WordBoundary => "\\b".to_string(),
        RegexLang::NotWordBoundary => "\\B".to_string(),
        RegexLang::FlagsStr(s) => s.clone(),
        RegexLang::Empty => "".to_string(),
        RegexLang::Num(_) => "".to_string(),
    }
}

/// Generate equivalent patterns from an input pattern using e-graph rewrites
/// Returns a vector of equivalent pattern strings (limited to min_patterns..max_patterns)
pub fn generate_equivalent_patterns(pattern: &str, iter_limit: usize, min_patterns: usize, max_patterns: usize) -> Result<Vec<String>, String> {
    // Convert pattern to RecExpr
    let expr = pattern_to_expr(pattern)?;
    
    // Perform rewrites and get the e-graph with root
    let (egraph, root) = perform_rewrites(&expr, iter_limit);
    
    // Extract expressions using the original root (no more rewrites needed)
    let expressions = extract_patterns(&egraph, root, min_patterns);
    
    // Convert back to pattern strings and deduplicate
    let mut patterns: Vec<String> = expressions.iter()
        .map(|expr| recexpr_to_pattern(expr))
        .filter(|p| !p.is_empty())
        .collect();
    
    patterns.sort();
    patterns.dedup();
    
    // Check if we have enough patterns
    if patterns.len() < min_patterns {
        return Err(format!("Not enough equivalent patterns found: {} < {}", patterns.len(), min_patterns));
    }
    
    // Limit the number of patterns returned
    patterns.truncate(max_patterns);
    
    Ok(patterns)
}
