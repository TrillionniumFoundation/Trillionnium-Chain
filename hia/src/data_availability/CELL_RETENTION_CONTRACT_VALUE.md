# Native Cell retention contract value

The private `trnm_cell_retention_contract_value_v1` computes the original
`CellRetentionContractV1::commitment(store_id)` for immutable declarations.
It is neither reservation, funding, custody, predecessor/successor
verification, nor approval to fetch, repair, retain or delete any object.

Call `f0(input, output, work)` with disjoint caller-owned spans. The input is:

| Offset | Field |
| ---: | --- |
| 0 | Eight bytes `NCRC0001` |
| 8, 40, 72 | Store ID, operation, funding operation (32 bytes each) |
| 104, 112, 120 | Retain-from height, retain-until height, maximum repair bytes (u64 big-endian) |
| 128 | Successor presence (0 absent, 1 present) |
| 129, 161 | Only if present: successor store and operation (32 bytes each) |
| 129 or 193 | One complete original TCM1 manifest, no tail |

The established native TCM1 decoder validates the complete manifest and
derives its original manifest ID. No supplied manifest ID is accepted.
The retention transcript is ASCII `trnm.cell-retention-contract.v1`, NUL,
the store/operation/funding IDs, the derived manifest ID, the three
integer fields, the option tag, and the two successor IDs only if present.
The helper checks neither term admissibility nor funding or store identity;
the original public value method does not check them either.

Success (0) writes the 32-byte SHA-256 commitment. It preserves any output
suffix and the work suffix beyond the minimum of 1457 bytes. Malformed
private framing returns 100; original TCM1 diagnostics 1 through 12
retain their meaning. A short output/work span returns 102. These refusals
leave input, output and work unchanged. Unexpected internal status 103
does not publish output. There is no I/O.
