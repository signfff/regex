use differential_testing::translate_pattern_to_other_language;
use libfuzzer_sys::Corpus;

fn differential_test(input: &[u8]){
    // Implementation of differential testing logic goes here
    let result = translate_pattern_to_other_language(input);
    match result {
        Corpus::Reject => {
            // 结束运行
        },
        Corpus::Keep=>{
            // 蜕变测试
        }
    }
}
fn main(){
    differential_test(b"aabb");
}
