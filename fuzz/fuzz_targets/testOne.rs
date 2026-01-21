use regex_fuzz::diff::*;
use regex_syntax::ast::parse::Parser;
use regex_syntax::ast::Ast;

fn main() {
    let manager = RegexLibManager::new();
    let pattern = "[a-z|a]|a[]-|a9]-";
    // let pattern = "[^\x00]";

    let ast = match Parser::new().parse(&pattern) {
        Ok(ast) => {
            println!("{:?}", ast);
            pretty_print_ast(&ast, 0);
            ast
        }
        Err(e) => {
            println!("parse error: {:?}", e);
            return;
        }
    };

    // 调用 validate_pattern 进行测试
    match validate_pattern(&manager, &pattern, &ast) {
        Ok(_) => println!("模式验证通过"),
        Err(e) => println!("模式验证失败: {:?}", e),
    }
}
fn pretty_print_ast(ast: &Ast, depth: usize) {
    let indent = format!("{}", "  ".repeat(depth));
    match ast {
        Ast::Empty(_) => println!("{}Empty", indent),

        Ast::Literal(lit) => println!("{}{:?}", indent, lit),

        Ast::Concat(concat) => {

            println!("{}Concat", indent);
            for a in &concat.asts {
                pretty_print_ast(a, depth + 1);
            }
            println!("{}", indent);
        }

        Ast::Alternation(alt) => {
            println!("{}Alternation", indent);
            for a in &alt.asts {
                pretty_print_ast(a, depth + 1);
            }
            println!("{}", indent);
        }

        Ast::Group(g) => {
            println!("{}Group", indent);
            pretty_print_ast(&g.ast, depth + 1);
            println!("{}", indent);
        }

        Ast::Repetition(rep) => {
            println!("{}Repetition", indent);
            pretty_print_ast(&rep.ast, depth + 1);
            println!("{}", indent);
        }

        Ast::Assertion(assert) => {
            println!("{}{:?}", indent, assert);
        }

        Ast::Dot(_) => {
            println!("{}Dot", indent);
        }

        Ast::Flags(flags) => {
            println!("{}{:?}", indent, flags);
        }

        Ast::ClassUnicode(class) => {
            println!("{}{:?}", indent, class);
        }

        Ast::ClassPerl(class) => {
            println!("{}{:?}", indent, class);
        }

        Ast::ClassBracketed(bracketed) => {
            println!("{}{:?}", indent, bracketed);
        }
    }
}
