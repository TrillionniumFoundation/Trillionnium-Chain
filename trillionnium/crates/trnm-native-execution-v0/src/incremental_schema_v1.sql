CREATE TABLE ni_meta (
          id INTEGER PRIMARY KEY CHECK(id=1), schema INTEGER NOT NULL CHECK(schema=1),
          chain BLOB NOT NULL, genesis BLOB NOT NULL CHECK(length(genesis)=32),
          namespace BLOB NOT NULL CHECK(length(namespace)=32), owner_generation BLOB NOT NULL CHECK(length(owner_generation)=8),
          head_height BLOB NOT NULL CHECK(length(head_height)=8), head_block BLOB NOT NULL CHECK(length(head_block)=32),
          head_version BLOB NOT NULL CHECK(length(head_version)=8), head_root BLOB NOT NULL CHECK(length(head_root)=32),
          commit_sequence BLOB NOT NULL CHECK(length(commit_sequence)=8), head_intent BLOB NOT NULL CHECK(length(head_intent)=32),
          head_checksum BLOB NOT NULL CHECK(length(head_checksum)=32)) STRICT;
        CREATE TABLE ni_nodes (
          node_key BLOB PRIMARY KEY, node_version BLOB NOT NULL CHECK(length(node_version)=8),
          node_bytes BLOB NOT NULL, node_hash BLOB NOT NULL CHECK(length(node_hash)=32),
          refs BLOB NOT NULL CHECK(length(refs)=8)) STRICT, WITHOUT ROWID;
        CREATE INDEX ni_nodes_version ON ni_nodes(node_version);
        CREATE TABLE ni_values (
          key_hash BLOB NOT NULL CHECK(length(key_hash)=32), version BLOB NOT NULL CHECK(length(version)=8),
          present INTEGER NOT NULL CHECK(present IN(0,1)), value BLOB NOT NULL,
          CHECK(present=1 OR length(value)=0), PRIMARY KEY(key_hash,version)) STRICT, WITHOUT ROWID;
        CREATE INDEX ni_values_version ON ni_values(version);
        CREATE TABLE ni_preimages (key_hash BLOB PRIMARY KEY CHECK(length(key_hash)=32),preimage BLOB NOT NULL) STRICT, WITHOUT ROWID;
        CREATE TABLE ni_roots (
          version BLOB PRIMARY KEY CHECK(length(version)=8), epoch BLOB NOT NULL CHECK(length(epoch)=8),
          consensus_height BLOB NOT NULL CHECK(length(consensus_height)=8), block_id BLOB NOT NULL CHECK(length(block_id)=32),
          root BLOB NOT NULL CHECK(length(root)=32), root_node_key BLOB NOT NULL,
          commit_sequence BLOB NOT NULL UNIQUE CHECK(length(commit_sequence)=8), intent BLOB NOT NULL UNIQUE CHECK(length(intent)=32)) STRICT, WITHOUT ROWID;
        CREATE UNIQUE INDEX ni_roots_block ON ni_roots(block_id);
        CREATE TABLE ni_prepared (
          artifact BLOB PRIMARY KEY CHECK(length(artifact)=32), parent_kind INTEGER NOT NULL CHECK(parent_kind IN(0,1)),
          parent_id BLOB NOT NULL CHECK(length(parent_id)=32), parent_height BLOB NOT NULL CHECK(length(parent_height)=8),
          parent_version BLOB NOT NULL CHECK(length(parent_version)=8), parent_root BLOB NOT NULL CHECK(length(parent_root)=32),
          anchor_version BLOB NOT NULL CHECK(length(anchor_version)=8), anchor_root BLOB NOT NULL CHECK(length(anchor_root)=32),
          owner_generation BLOB NOT NULL CHECK(length(owner_generation)=8), profile BLOB NOT NULL CHECK(length(profile)=32),
          target_height BLOB NOT NULL CHECK(length(target_height)=8), block_id BLOB NOT NULL CHECK(length(block_id)=32),
          delta BLOB NOT NULL, delta_hash BLOB NOT NULL CHECK(length(delta_hash)=32), expected_root BLOB NOT NULL CHECK(length(expected_root)=32),
          persist_sequence BLOB NOT NULL UNIQUE CHECK(length(persist_sequence)=8), phase INTEGER NOT NULL CHECK(phase IN(0,1)),
          edge BLOB CHECK(edge IS NULL OR length(edge)=32)) STRICT, WITHOUT ROWID;
        CREATE INDEX ni_prepared_parent ON ni_prepared(parent_kind,parent_id);
        CREATE INDEX ni_prepared_phase ON ni_prepared(phase);
        CREATE UNIQUE INDEX ni_prepared_block ON ni_prepared(block_id);
        CREATE TABLE ni_commit (
          operation BLOB PRIMARY KEY CHECK(length(operation)=32), predecessor_checksum BLOB NOT NULL CHECK(length(predecessor_checksum)=32),
          expected_sequence BLOB NOT NULL CHECK(length(expected_sequence)=8), artifact BLOB NOT NULL CHECK(length(artifact)=32),
          target_block BLOB NOT NULL CHECK(length(target_block)=32), target_root BLOB NOT NULL CHECK(length(target_root)=32),
          successor_sequence BLOB NOT NULL UNIQUE CHECK(length(successor_sequence)=8), result BLOB NOT NULL) STRICT, WITHOUT ROWID;
        CREATE TABLE ni_pin (
          owner BLOB NOT NULL CHECK(length(owner)=32), reason INTEGER NOT NULL CHECK(reason IN(0,1,2,3,4,5)),
          version BLOB NOT NULL CHECK(length(version)=8), root BLOB NOT NULL CHECK(length(root)=32),
          reference_count BLOB NOT NULL CHECK(length(reference_count)=8 AND reference_count>x'0000000000000000'),
          release_authority BLOB CHECK(release_authority IS NULL OR length(release_authority)=32),
          PRIMARY KEY(owner,reason,version)) STRICT, WITHOUT ROWID;
        CREATE INDEX ni_pin_version ON ni_pin(version);
        CREATE TABLE ni_epoch_edge (
          strict_binding BLOB PRIMARY KEY CHECK(length(strict_binding)=32), edge BLOB NOT NULL, checksum BLOB NOT NULL CHECK(length(checksum)=32),
          checkpoint_version BLOB NOT NULL CHECK(length(checkpoint_version)=8), first_height BLOB NOT NULL CHECK(length(first_height)=8),
          phase INTEGER NOT NULL CHECK(phase IN(0,1)), committed_block BLOB CHECK(committed_block IS NULL OR length(committed_block)=32),
          CHECK((phase=0 AND committed_block IS NULL) OR (phase=1 AND committed_block IS NOT NULL))) STRICT, WITHOUT ROWID;
        CREATE TABLE ni_gc_queue (
          node_key BLOB PRIMARY KEY, enqueued_generation BLOB NOT NULL CHECK(length(enqueued_generation)=8),
          expected_hash BLOB NOT NULL CHECK(length(expected_hash)=32)) STRICT, WITHOUT ROWID;

CREATE TABLE ni_imported_root (
  version BLOB PRIMARY KEY CHECK(length(version)=8),
  source_anchor BLOB NOT NULL CHECK(length(source_anchor)=32),
  result BLOB NOT NULL CHECK(length(result)=144),
  checksum BLOB NOT NULL CHECK(length(checksum)=32)
) STRICT, WITHOUT ROWID;
CREATE TABLE ni_sequence (
  id INTEGER PRIMARY KEY CHECK(id=1),
  persist_sequence BLOB NOT NULL CHECK(length(persist_sequence)=8)
) STRICT;
