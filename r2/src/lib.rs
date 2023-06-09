use nom::character::complete::hex_digit1;
use nom::combinator::{all_consuming, complete};
use nom::sequence::preceded;
use nom::{branch::alt, combinator::map};
use nom::{bytes::complete::tag, character::complete::digit1};
use r2_client::RichRevisionId;

use eyre::Result;

pub fn parse_ref(ref_: &str) -> Result<RichRevisionId> {
    let head_parser = preceded::<_, _, _, (_, nom::error::ErrorKind), _, _>(
        tag("HEAD~"),
        map(digit1, |s: &str| {
            RichRevisionId::RelativeHead(s.parse::<usize>().unwrap())
        }),
    );

    let remote_head_parser = preceded::<_, _, _, (_, nom::error::ErrorKind), _, _>(
        tag("remote/HEAD~"),
        map(digit1, |s: &str| {
            RichRevisionId::RelativeRemoteHead(s.parse::<usize>().unwrap())
        }),
    );

    let head_parser_0 = map(tag("HEAD"), |_| RichRevisionId::RelativeHead(0));

    let remote_head_parser_0 = map(tag("remote/HEAD"), |_| {
        RichRevisionId::RelativeRemoteHead(0)
    });

    let current_parser = map(tag("current"), |_| RichRevisionId::Uncommitted);

    let commit_id_parser = map(hex_digit1, |s: &str| RichRevisionId::CommitId(s.to_owned()));

    let parse = alt((
        head_parser,
        head_parser_0,
        remote_head_parser,
        remote_head_parser_0,
        current_parser,
        commit_id_parser,
    ));
    Ok(all_consuming(parse)(&ref_).map_err(|e| e.to_owned())?.1)
}
