use anyhow::{Context, Result, ensure};
use num_bigint::BigInt;
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};
use winnow::{
    Parser,
    ascii::{digit1, multispace0},
    combinator::{
        alt, cut_err, delimited, eof, fail, opt, preceded, repeat, separated, terminated,
    },
    error::StrContext,
    stream::Stateful,
};

// These are evaluation budgets, not machine integer widths.
const MAX_BITS: u64 = 65536;
const MAX_NODES: usize = 1024;
const MAX_DEPTH: usize = 64;

type Input<'a> = Stateful<&'a str, Syntax>;
#[derive(Default, Debug)]
struct Syntax {
    nodes: Vec<Node>,
    depth: usize,
}
#[derive(Debug)]
enum Node {
    Literal(BigInt),
    Unary(bool, usize),
    Binary(Op, usize, usize),
}
#[derive(Clone, Copy, Debug)]
enum Op {
    Add,
    Sub,
    Mul,
    Div,
    FloorDiv,
    Mod,
    Pow,
}
#[derive(Clone, Copy)]
enum Bound {
    Min,
    Max,
}

fn node(input: &mut Input<'_>, value: Node) -> winnow::ModalResult<usize> {
    if input.state.nodes.len() == MAX_NODES {
        return cut_err(fail.context(StrContext::Label("integer expression resource limit")))
            .parse_next(input);
    }
    let id = input.state.nodes.len();
    input.state.nodes.push(value);
    Ok(id)
}

fn expression(input: &mut Input<'_>) -> winnow::ModalResult<usize> {
    let mut value = product(input)?;
    let rest: Vec<_> = repeat(
        0..,
        (
            alt(('+'.value(Op::Add), '-'.value(Op::Sub))),
            cut_err(product),
        ),
    )
    .parse_next(input)?;
    for (op, rhs) in rest {
        value = node(input, Node::Binary(op, value, rhs))?;
    }
    Ok(value)
}

fn product(input: &mut Input<'_>) -> winnow::ModalResult<usize> {
    let mut value = unary(input)?;
    let rest: Vec<_> = repeat(
        0..,
        (
            alt((
                "//".value(Op::FloorDiv),
                '*'.value(Op::Mul),
                '/'.value(Op::Div),
                '%'.value(Op::Mod),
            )),
            cut_err(unary),
        ),
    )
    .parse_next(input)?;
    for (op, rhs) in rest {
        value = node(input, Node::Binary(op, value, rhs))?;
    }
    Ok(value)
}

fn unary(input: &mut Input<'_>) -> winnow::ModalResult<usize> {
    if input.state.depth == MAX_DEPTH {
        return cut_err(fail.context(StrContext::Label("integer expression depth limit")))
            .parse_next(input);
    }
    input.state.depth += 1;
    let result = preceded(multispace0, alt((signed, power))).parse_next(input);
    input.state.depth -= 1;
    result
}

fn signed(input: &mut Input<'_>) -> winnow::ModalResult<usize> {
    let (negative, value) =
        (alt(('-'.value(true), '+'.value(false))), cut_err(unary)).parse_next(input)?;
    node(input, Node::Unary(negative, value))
}

fn power(input: &mut Input<'_>) -> winnow::ModalResult<usize> {
    let lhs = terminated(
        alt((literal, delimited('(', cut_err(expression), cut_err(')')))),
        multispace0,
    )
    .parse_next(input)?;
    let rhs = opt(preceded("**", cut_err(unary))).parse_next(input)?;
    match rhs {
        Some(rhs) => node(input, Node::Binary(Op::Pow, lhs, rhs)),
        None => Ok(lhs),
    }
}

fn literal(input: &mut Input<'_>) -> winnow::ModalResult<usize> {
    let value = digit1.parse_to::<BigInt>().parse_next(input)?;
    node(input, Node::Literal(value))
}

fn bound(input: &mut Input<'_>) -> winnow::ModalResult<(Bound, usize)> {
    let name = delimited(
        multispace0,
        alt((
            "min_inclusive".value(Bound::Min),
            "max_exclusive".value(Bound::Max),
        )),
        multispace0,
    )
    .context(StrContext::Label("min_inclusive= or max_exclusive= bound"))
    .parse_next(input)?;
    let value = preceded('=', cut_err(expression)).parse_next(input)?;
    Ok((name, value))
}

pub(super) fn bounds(source: &str) -> Result<(Option<BigInt>, Option<BigInt>)> {
    let mut input = Input {
        input: source,
        state: Syntax::default(),
    };
    let parsed: Vec<_> = terminated(separated(0..=2, bound, ','), (multispace0, eof))
        .parse_next(&mut input)
        .map_err(|error| {
            anyhow::anyhow!(
                "integer bounds at byte {}: {error}",
                source.len() - input.input.len()
            )
        })?;
    let values = evaluate(input.state.nodes)?;
    let (mut min, mut max) = (None, None);
    for (name, id) in parsed {
        let slot = match name {
            Bound::Min => &mut min,
            Bound::Max => &mut max,
        };
        ensure!(slot.is_none(), "duplicate integer bound keyword");
        *slot = Some(values[id].clone());
    }
    Ok((min, max))
}

fn evaluate(nodes: Vec<Node>) -> Result<Vec<BigInt>> {
    let mut values: Vec<BigInt> = Vec::with_capacity(nodes.len());
    for node in nodes {
        let value = match node {
            Node::Literal(value) => value,
            Node::Unary(negative, id) => {
                if negative {
                    -&values[id]
                } else {
                    values[id].clone()
                }
            }
            Node::Binary(op, lhs, rhs) => {
                let (left, right) = (&values[lhs], &values[rhs]);
                match op {
                    Op::Add => left + right,
                    Op::Sub => left - right,
                    Op::Mul => left * right,
                    Op::Pow => {
                        ensure!(*right >= BigInt::ZERO, "negative integer exponent");
                        if right.is_zero() {
                            BigInt::ONE
                        } else if left.is_zero() || *left == BigInt::ONE {
                            left.clone()
                        } else if *left == BigInt::NEG_ONE {
                            if right.is_even() {
                                BigInt::ONE
                            } else {
                                BigInt::NEG_ONE
                            }
                        } else {
                            let exponent = right
                                .to_u32()
                                .context("integer expression resource limit exceeded")?;
                            ensure!(
                                left.bits().saturating_mul(u64::from(exponent)) <= MAX_BITS,
                                "integer expression resource limit exceeded"
                            );
                            left.pow(exponent)
                        }
                    }
                    Op::Div | Op::FloorDiv | Op::Mod => {
                        ensure!(!right.is_zero(), "division by zero in integer expression");
                        let (quotient, remainder) = left.div_mod_floor(right);
                        match op {
                            Op::Div => {
                                ensure!(
                                    remainder.is_zero(),
                                    "integer division is not exact; use // for floor division"
                                );
                                quotient
                            }
                            Op::FloorDiv => quotient,
                            Op::Mod => remainder,
                            _ => unreachable!(),
                        }
                    }
                }
            }
        };
        ensure!(
            value.bits() <= MAX_BITS,
            "integer expression resource limit exceeded"
        );
        values.push(value);
    }
    Ok(values)
}
