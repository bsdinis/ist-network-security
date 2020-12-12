use nom::character::complete::hex_digit1;
use nom::combinator::{complete, eof, value};
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
    let mut parse = complete(parse);

    let ref_ = parse(ref_)
        .and_then(|(leftovers, res)| {
            if leftovers.len() != 0 {
                Err(nom::Err::Error((leftovers, nom::error::ErrorKind::Eof)))
            } else {
                Ok(res)
            }
        })
        .map_err(|e| e.to_owned())?;
    Ok(ref_)
}
