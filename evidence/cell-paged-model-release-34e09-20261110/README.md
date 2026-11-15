# Optimized build: bounded real-model paged restoration

Source `8dee97636e2b6932fb7a22b1b54f2cab09ae8406` was compiled with Cargo `--release` using pinned Linux Rust 1.95 and the original PQ provider/offline dependencies. No runtime source or acceptance predicate changed. Both example entries (11 cases each, including six shared new cases), 11 paged-consumer cases, DA823, Node44, strict release Clippy, fmt, source negatives and repository/link checks passed on this exact source. Start/end source manifests match.

## Fresh real operation

Fresh operation `9c234088530666a943673af5c70a873e7bb706e13beddb6480469265789ef2fe` retained the original 280,269,602 bytes, 30 manifests, 95 chunks and TCV1/TCV2/CTS1/BEP52 plan. The same original absolute 300-second clock includes source packing, catalog ACK, plan construction, every repeated RS encoding, staging, all six target publications, cold recovery, complete readback and two sealed forwards. Compilation and evidence packaging are outside that operation and recorded separately. Payload 512 MiB, worker RSS 8 GiB and four worker threads were unchanged. The successful worker received only the remaining original wall budget.

Native wait4: 36.047064473 seconds, exit0, 26.020225 user CPU seconds plus 6.988784 system CPU seconds, maximum RSS 1,421,016 KiB. These are this operation's process-accounting observations, not a universal performance bound or simultaneous process-tree RSS.

All 570 target publications completed. Only this operation's slots1/3 were isolated; its catalog payload arena was zeroed at unchanged length; its source, delivery and staging caches were removed. Four reopened original providers at slots0/2/4/5 supplied 380 verified actual shard reads through 570 logical callbacks (190 unavailable). All95 consumer chunks and original full TCV2/pages/catalog checks passed. Original CTS1/CHB1 handoff then completed two actual sealed model forwards. The supervisor records an exit-time RSS observation gap and explicit terminal wait4 reconciliation; raw records are retained, not silently treated as continuous memory observation.

Restore reservation: 420,450,624 input bytes, 700,720,226 reconstruction bytes, 560,539,204 cache-I/O bytes and 280,269,602 final-readback bytes. Actual obtained shard wire was 280,300,416 bytes. Custody elapsed16,208ms; whole-operation custody observation22,681ms; native process elapsed35,824ms. These intervals and budgets are distinct.

## Boundaries

The earlier debug operation01 failed at the original300s deadline; its partial target duties and history remain unchanged in the parent evidence. This optimized-build success neither relabels that attempt nor establishes a paired statistical speedup estimate. Six local directories do not establish six independent operators/failure domains. The interpreter/native dependency snapshot was independently pinned on the original host, not delivered as sealed transport. Consumer success grants no custody settlement, M12 funding, ordinary Hepta FinalUse, selection, reward, installation or production authority. Independent operators/WAN and the real paid lifecycle remain HOLD.
