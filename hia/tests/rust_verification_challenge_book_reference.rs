// The original ChallengeBook and per-record methods are prefixed by the test.
// SHA, fixed-size reads and canonical fixture encoding are reused from the record adapter.
fn execute(book: &mut ChallengeBookV1, request: &[u8]) -> VerificationProfileResultV1<[u8; 32]> {
    let data = &request[24..197];
    let result_id = array(data, 32);
    match request[201] {
        0 => {
            book.open(
                array(data, 0),
                result_id,
                array(data, 64),
                number(data, 96),
                number(request, 16),
                number(data, 104),
                number(data, 112),
                number(data, 120),
                number(data, 128),
            )?;
        }
        1 => {
            book.get_mut(&result_id)?;
        }
        2 => {
            let record = book.get_mut(&result_id)?;
            let height = number(request, 8);
            match request[4] {
                1 => record.submit_evidence(height),
                2 => record.begin_response(height),
                3 => record.submit_response(height),
                4 => {
                    use ChallengeFinalOutcomeV1::*;
                    let category = match request[5] {
                        1 => Upheld,
                        2 => Rejected,
                        3 => Withdrawn,
                        4 => Expired,
                        _ => panic!("untyped decision choice"),
                    };
                    record.decide(height, category)
                }
                5 => record.appeal(height, number(request, 16)),
                6 => record.finalize(height),
                7 => record.withdraw(),
                8 => record.expire(height),
                _ => panic!("untyped record action"),
            }?;
        }
        _ => panic!("invalid oracle operation"),
    }
    Ok(result_id)
}
fn main() -> io::Result<()> {
    let mut bytes = Vec::new();
    io::stdin().read_to_end(&mut bytes)?;
    assert_eq!(bytes.len() % 205, 0);
    let mut out = io::stdout().lock();
    let mut book = ChallengeBookV1::default();
    for request in bytes.chunks_exact(205) {
        let before = book.clone();
        match execute(&mut book, request) {
            Ok(selected) => {
                let index = book
                    .by_result
                    .keys()
                    .position(|key| key == &selected)
                    .unwrap();
                if request[201] == 1 {
                    assert_eq!(before, book);
                }
                out.write_all(&[
                    0,
                    book.by_result.len().try_into().unwrap(),
                    index.try_into().unwrap(),
                ])?;
                out.write_all(&[0; 6])?;
                for row in book.by_result.values() {
                    assert!(!row.economic_authority && !row.order_reorg);
                    encode(row, &mut out)?;
                }
                encode(book.by_result.get(&selected).unwrap(), &mut out)?;
            }
            Err(err) => {
                assert_eq!(before, book);
                use VerificationProfileErrorV1::*;
                let code = match err {
                    ZeroIdentifier => 1,
                    InvalidChallengePhase => 17,
                    ChallengeDeadlineMissed => 18,
                    DuplicateChallenge => 20,
                    AppealAlreadyUsed => 19,
                    ChallengeNotFound => 21,
                    _ => panic!("unexpected book error: {err}"),
                };
                out.write_all(&[code])?;
            }
        }
    }
    Ok(())
}
