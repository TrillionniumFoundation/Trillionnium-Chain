CREATE TABLE epoch_metadata (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 journal BLOB NOT NULL CHECK(length(journal)=32),
 profile BLOB NOT NULL CHECK(length(profile)=32),
 source_kind INTEGER NOT NULL CHECK(source_kind BETWEEN 0 AND 2),
 source_journal BLOB NOT NULL CHECK(length(source_journal)=32),
 source_chain BLOB NOT NULL CHECK(length(source_chain)=32),
 source_record BLOB NOT NULL CHECK(length(source_record)>0),
 source_transition BLOB NOT NULL CHECK(length(source_transition)>0),
 origin BLOB NOT NULL CHECK(length(origin)=32),
 first_revision INTEGER NOT NULL CHECK(first_revision>0)
) STRICT;
CREATE TABLE epoch_provenance (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 provenance BLOB NOT NULL CHECK(length(provenance)>0 AND length(provenance)<=67108864)
) STRICT;
CREATE TABLE epoch_records (
 revision INTEGER PRIMARY KEY CHECK(revision>0),
 predecessor BLOB NOT NULL CHECK(length(predecessor)=32),
 chain BLOB NOT NULL CHECK(length(chain)=32),
 provenance_id INTEGER NOT NULL CHECK(provenance_id=1),
 record_before BLOB NOT NULL CHECK(length(record_before)>0),
 record_after BLOB NOT NULL CHECK(length(record_after)>=32),
 transition BLOB NOT NULL CHECK(length(transition)>0)
) STRICT;
CREATE TABLE epoch_head (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 revision INTEGER NOT NULL CHECK(revision>0),
 chain BLOB NOT NULL CHECK(length(chain)=32)
) STRICT;
