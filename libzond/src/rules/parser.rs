use super::{
    CreateNew, LANGUAGE_VERSION, Parameter, Part, Requirement, Rule, Token, TypeDefinition,
    TypeKind, Word, integer, types,
};
use std::collections::BTreeMap;
use winnow::{
    Parser,
    combinator::{
        alt, cut_err, delimited, eof, opt, peek, preceded, repeat, separated, terminated,
    },
    error::StrContext,
    token::any,
};

type Input<'a> = &'a [Token];

fn word(input: &mut Input<'_>) -> winnow::ModalResult<Word> {
    any.verify_map(|token| match token {
        Token::Word(word) => Some(word),
        _ => None,
    })
    .context(StrContext::Label("word"))
    .parse_next(input)
}
fn literal(input: &mut Input<'_>) -> winnow::ModalResult<String> {
    word.verify_map(|word| word.literal().map(str::to_owned))
        .context(StrContext::Label("literal"))
        .parse_next(input)
}
fn keyword(expected: &'static str) -> impl FnMut(&mut Input<'_>) -> winnow::ModalResult<()> {
    move |input| {
        literal
            .verify(|text: &str| text == expected)
            .void()
            .context(StrContext::Label(expected))
            .parse_next(input)
    }
}
fn symbol(expected: char) -> impl FnMut(&mut Input<'_>) -> winnow::ModalResult<()> {
    move |input| {
        any.verify(|token| token == &Token::Symbol(expected))
            .void()
            .parse_next(input)
    }
}
fn newline(input: &mut Input<'_>) -> winnow::ModalResult<()> {
    any.verify(|token| token == &Token::Newline)
        .void()
        .parse_next(input)
}
fn lines(input: &mut Input<'_>) -> winnow::ModalResult<()> {
    repeat(0.., newline).map(|(): ()| ()).parse_next(input)
}
fn end_line(input: &mut Input<'_>) -> winnow::ModalResult<()> {
    alt((repeat(1.., newline).map(|(): ()| ()), peek(symbol('}'))))
        .context(StrContext::Label("end of statement"))
        .parse_next(input)
}
fn integer_type(input: &mut Input<'_>) -> winnow::ModalResult<TypeKind> {
    let bounds = opt(any.verify_map(|token| match token {
        Token::IntegerBounds(source) => Some(source),
        _ => None,
    }))
    .try_map(|source| {
        source
            .map(|source| integer::bounds(&source))
            .unwrap_or(Ok((None, None)))
            .map_err(|error| std::io::Error::other(error.to_string()))
    })
    .parse_next(input)?;
    Ok(TypeKind::Integer {
        min: bounds.0,
        max: bounds.1,
    })
}
fn enum_type(input: &mut Input<'_>) -> winnow::ModalResult<TypeKind> {
    delimited(
        (symbol('{'), lines),
        terminated(
            separated(
                1..=types::MAX_CHOICES,
                terminated(literal, lines),
                (symbol(','), lines),
            ),
            opt((symbol(','), lines)),
        ),
        symbol('}'),
    )
    .map(|values| TypeKind::Enum { values })
    .parse_next(input)
}
fn length(input: &mut Input<'_>) -> winnow::ModalResult<usize> {
    literal
        .try_map(|value| value.parse::<usize>())
        .parse_next(input)
}
fn text_type(input: &mut Input<'_>) -> winnow::ModalResult<TypeKind> {
    delimited(
        symbol('('),
        (
            literal,
            preceded(symbol(','), length),
            preceded(symbol(','), length),
        ),
        symbol(')'),
    )
    .map(|(pattern, min, max)| TypeKind::Text { pattern, min, max })
    .parse_next(input)
}
fn choice_row(input: &mut Input<'_>) -> winnow::ModalResult<(String, Vec<String>)> {
    terminated(
        (
            literal,
            preceded(
                keyword("="),
                delimited(
                    symbol('('),
                    separated(1..=types::MAX_FIELDS, literal, symbol(',')),
                    symbol(')'),
                ),
            ),
        ),
        end_line,
    )
    .parse_next(input)
}
fn choice_type(input: &mut Input<'_>) -> winnow::ModalResult<TypeKind> {
    let fields = delimited(
        symbol('('),
        separated(1..=types::MAX_FIELDS, literal, symbol(',')),
        symbol(')'),
    )
    .parse_next(input)?;
    let rows: Vec<_> = delimited(
        (symbol('{'), lines),
        repeat(1..=types::MAX_CHOICES, choice_row),
        symbol('}'),
    )
    .parse_next(input)?;
    let cases: BTreeMap<_, _> = rows.iter().cloned().collect();
    if rows.len() != cases.len() {
        return cut_err(
            winnow::combinator::fail.context(StrContext::Label("distinct choice cases")),
        )
        .parse_next(input);
    }
    Ok(TypeKind::Choice { fields, cases })
}
fn definition(input: &mut Input<'_>) -> winnow::ModalResult<TypeDefinition> {
    preceded(
        keyword("type"),
        cut_err((
            literal,
            preceded(
                keyword("="),
                alt((
                    preceded(keyword("integer"), cut_err(integer_type)),
                    preceded(keyword("enum"), cut_err(enum_type)),
                    preceded(keyword("text"), cut_err(text_type)),
                    preceded(keyword("choice"), cut_err(choice_type)),
                    literal.map(|target| TypeKind::Alias { target }),
                )),
            ),
        )),
    )
    .map(|(name, definition)| TypeDefinition { name, definition })
    .parse_next(input)
}
fn parameter(input: &mut Input<'_>) -> winnow::ModalResult<Parameter> {
    (literal, preceded(symbol(':'), literal))
        .map(|(name, kind)| Parameter { name, kind })
        .parse_next(input)
}
fn requirement(input: &mut Input<'_>) -> winnow::ModalResult<Requirement> {
    preceded(
        keyword("require"),
        cut_err(terminated((literal, word), end_line)),
    )
    .map(|(kind, path)| Requirement { kind, path })
    .parse_next(input)
}
fn executable(input: &mut Input<'_>) -> winnow::ModalResult<String> {
    word.try_map(|word| {
        executable_word(word).map_err(|error| std::io::Error::other(error.to_string()))
    })
    .parse_next(input)
}
fn executable_word(word: Word) -> anyhow::Result<String> {
    if let Some(text) = word.literal() {
        return Ok(text.into());
    }
    if word.0.first() == Some(&Part::Variable("HOME".into())) {
        let mut text = String::from("~");
        for part in word.0.iter().skip(1) {
            let Part::Literal(value) = part else {
                anyhow::bail!("executable cannot use a parameter")
            };
            text.push_str(value);
        }
        anyhow::ensure!(
            text == "~" || text.starts_with("~/"),
            "invalid home-relative executable"
        );
        return Ok(text);
    }
    anyhow::bail!("executable must be literal; parameters cannot select a program")
}
struct Run {
    program: String,
    args: Vec<Word>,
    sudo_password: bool,
}
fn run(input: &mut Input<'_>) -> winnow::ModalResult<Run> {
    preceded(
        keyword("run"),
        cut_err(terminated(
            (opt(keyword("--sudo")), executable, repeat(0..=256, word)),
            end_line,
        )),
    )
    .map(|(sudo, program, args)| Run {
        program,
        args,
        sudo_password: sudo.is_some(),
    })
    .parse_next(input)
}
fn create(input: &mut Input<'_>) -> winnow::ModalResult<(Option<CreateNew>, Run)> {
    preceded(
        alt((keyword("create-new-dir"), keyword("create-new"))),
        cut_err((
            word,
            preceded(keyword("as"), literal),
            delimited((symbol('{'), lines), run, (symbol('}'), lines)),
        )),
    )
    .map(|(path, variable, run)| (Some(CreateNew { path, variable }), run))
    .parse_next(input)
}
fn rule(input: &mut Input<'_>) -> winnow::ModalResult<Rule> {
    lines.parse_next(input)?;
    let types = repeat(0..=types::MAX_TYPES, terminated(definition, end_line)).parse_next(input)?;
    keyword("rule").parse_next(input)?;
    let (name, parameters, requirements, (create_new, run)) = cut_err((
        literal,
        delimited(
            symbol('('),
            separated(0..=16, parameter, symbol(',')),
            symbol(')'),
        ),
        preceded((symbol('{'), lines), repeat(0..=16, requirement)),
        terminated(
            alt((create, run.map(|run| (None, run)))),
            (symbol('}'), lines, eof),
        ),
    ))
    .parse_next(input)?;
    Ok(Rule {
        name,
        language_version: LANGUAGE_VERSION,
        types,
        parameters,
        requirements,
        create_new,
        program: run.program,
        args: run.args,
        sudo_password: run.sudo_password,
    })
}

pub(super) fn parse(tokens: &[Token]) -> anyhow::Result<Rule> {
    let mut input = tokens;
    rule.parse_next(&mut input).map_err(|error| {
        anyhow::anyhow!(
            "rule syntax at token {}: {error}",
            tokens.len() - input.len()
        )
    })
}
