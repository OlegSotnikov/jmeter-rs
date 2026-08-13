#![no_main]

//! Bounded JMeter expression scanner/evaluator target.
//!
//! No filesystem, clock, random, network, script, or JVM capability is
//! installed.  Undefined variables/functions therefore remain data and are
//! safe for a parser boundary fuzz run.  Fixed probes assert the evaluator's
//! input, nesting, expansion, output, undefined-reference, and literal
//! progress invariants in addition to exercising the fuzzed expression.
//!
//! Invariants: `EXPR-UNDEFINED-001` preserves unresolved names,
//! `EXPR-LIMITS-001` exercises input/expansion/nesting/output limits, and
//! `EXPR-PROGRESS-001` checks literal no-reference progress.
//! Source-side coverage: expression bytes, undefined references, literal
//! progress, and each bounded evaluator counter are checked independently.
//! I/O policy: none; variables, properties, and functions are in-memory stubs.

use jmeter_rs_expr::{
    BuiltinFunctions, ErrorCode, EvaluationLimits, NoFunctions, NoProperties, NoVariables, expand,
};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 64 * 1024;

fn limits() -> EvaluationLimits {
    EvaluationLimits::new(MAX_INPUT_BYTES, 16, 256, 128 * 1024)
}

fn expect_error_code(
    input: &str,
    functions: &dyn jmeter_rs_expr::FunctionResolver,
    limits: EvaluationLimits,
    expected: ErrorCode,
) {
    let error = expand(input, &NoVariables, &NoProperties, functions, limits)
        .expect_err("bounded expression probe unexpectedly succeeded");
    if error.code() != expected {
        panic!(
            "expression probe returned {}, expected {}",
            error.code(),
            expected
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(input) = std::str::from_utf8(data) else {
        // The expression API accepts UTF-8 text.  Do not turn malformed bytes
        // into replacement characters and accidentally fuzz a different
        // expression than the one supplied.
        return;
    };
    let limits = limits();

    if input.len() > MAX_INPUT_BYTES {
        expect_error_code(input, &NoFunctions, limits, ErrorCode::InputLimit);
        return;
    }

    // An undefined variable or function is a preserved source reference, not
    // an empty/default value.  This invariant protects extension names from
    // being silently rewritten by the fuzz boundary.
    let undefined = "${FUZZ_UNDEFINED}:${__fuzz_undefined(a,b)}";
    let preserved = expand(undefined, &NoVariables, &NoProperties, &NoFunctions, limits)
        .expect("undefined expression probe should be bounded");
    if preserved != undefined {
        panic!("undefined expression reference was rewritten");
    }

    // Explicit limit probes cover each finite counter independently.  The
    // nesting probe uses the pure built-in __eval indirection without adding
    // any external capability.
    expect_error_code(
        "${A}${B}",
        &NoFunctions,
        EvaluationLimits::new(MAX_INPUT_BYTES, 16, 1, 128 * 1024),
        ErrorCode::ExpansionLimit,
    );
    expect_error_code(
        "${__eval(${__eval(x)})}",
        &BuiltinFunctions::new(),
        EvaluationLimits::new(MAX_INPUT_BYTES, 1, 16, 128 * 1024),
        ErrorCode::NestingLimit,
    );
    expect_error_code(
        "${__intSum(123,456)}",
        &BuiltinFunctions::new(),
        EvaluationLimits::new(MAX_INPUT_BYTES, 16, 16, 2),
        ErrorCode::OutputLimit,
    );

    // A literal-only expression must be returned unchanged.  This gives the
    // scanner a deterministic no-reference progress check independent of the
    // fuzzed syntax and the function registry.
    let literal = "fuzz literal / UTF-8 ☃";
    let literal_output = expand(literal, &NoVariables, &NoProperties, &NoFunctions, limits)
        .expect("literal expression should be bounded");
    if literal_output != literal {
        panic!("literal expression changed while scanning");
    }

    // Exercise both the native registry and the no-function policy on the
    // fuzzed source.  Successful output is always bounded by the same policy
    // that was supplied to the evaluator.
    let builtins = BuiltinFunctions::new();
    let no_functions = NoFunctions;
    for functions in [
        &builtins as &dyn jmeter_rs_expr::FunctionResolver,
        &no_functions as &dyn jmeter_rs_expr::FunctionResolver,
    ] {
        if let Ok(output) = expand(input, &NoVariables, &NoProperties, functions, limits)
            && output.len() > limits.max_output_bytes
        {
            panic!("expression evaluator exceeded its output bound");
        }
    }
});
