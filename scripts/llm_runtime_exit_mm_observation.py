"""V5 same-sample PF_EXITING frontier; detached mm is not released memory.

Only the original held-pidfd owner can borrow this observation. Every task's
PF_EXITING/starttime/stat frontier precedes the original missing-RSS read.
Stable-group closure reuses V2's FD lifecycle and double-frontier checks. It
does not replace V3/V4 worker retirement or prove arbitrary process descendants.
"""
import os
import time

import llm_runtime_exit_observation as base

PROFILE = 'linux-owned-exit-mm-detached-v5'
MAX_DRAIN_NS = base.MAX_DRAIN_NS


def _exiting(row):
    return (row['flags'] & base.PF_EXITING and not row['flags'] & base.PF_KTHREAD
            and row['vsize'] == row['rss'] == 0 and row['state'] in 'RSDZ')


class _BeforeStatusSample:
    """Private retained descriptors, not reconstructible from a diagnostic dict."""

    def __init__(self, pid, held_pidfd, owner_token):
        self.pid, self.held_pidfd, self.owner_token = pid, held_pidfd, owner_token
        self.group_fd, self.tasks_fd, self.task_fds = None, None, {}
        self.closed, self.before = False, {}
        self.names, self.signatures = (), {}
        try:
            base._require(owner_token is not None, 'exit-mm-owner')
            self.held_signature = base._signature(held_pidfd)
            self.identity = base._pidfd_identity(pid, held_pidfd)
            self.visible, self.parent, self.namespace = self.identity
            self.group_fd = base._open_group(self.visible)
            self.group_signature = base._signature(self.group_fd)
            leader = base._stat(base._read(self.group_fd, 'stat'))
            base._require(leader['pid'] == self.visible and leader['ppid'] == self.parent,
                          'exit-mm-prior-identity')
            self.prior_leader = leader
            if _exiting(leader):
                self.tasks_fd = os.open('task', os.O_RDONLY | os.O_DIRECTORY |
                    os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.group_fd)
                self.tasks_signature = base._signature(self.tasks_fd)
                self.names = base._task_names(self.tasks_fd)
                base._require(str(self.visible) in self.names, 'exit-leader-not-in-task-set')
                for name in self.names:
                    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY |
                        os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.tasks_fd)
                    self.task_fds[name] = descriptor
                    self.signatures[name] = base._signature(descriptor)
                    row = base._stat(base._read(descriptor, 'stat'))
                    base._require(row['pid'] == int(name) and row['ppid'] == self.parent
                                  and _exiting(row), 'exit-mm-prior-frontier')
                    self.before[name] = row
                base._require(base._task_names(self.tasks_fd) == self.names,
                              'exit-task-set')
            self.frontier_completed_ns = time.monotonic_ns()
            # This is the original RSS status read, after the entire stat frontier.
            self.fields = base._status(base._read(self.group_fd, 'status'))
            self.sample_started_ns = time.monotonic_ns()
            base._require(base._signature(held_pidfd) == self.held_signature and
                base._pidfd_identity(pid, held_pidfd) == self.identity, 'exit-owner-changed')
        except BaseException:
            self.close()
            raise

    def finish(self, initial_leader, missing_sample_ns):
        base._require(not self.closed and initial_leader is self.fields
            and missing_sample_ns == self.sample_started_ns and 'VmRSS' not in self.fields
            and self.before and tuple(self.before) == self.names
            and self.frontier_completed_ns <= missing_sample_ns,
            'exit-mm-no-prior-frontier')
        self._held()
        return MmDetachedObservation(self, initial_leader, missing_sample_ns)

    def _held(self):
        base._require(not self.closed and
            base._signature(self.held_pidfd) == self.held_signature and
            base._pidfd_identity(self.pid, self.held_pidfd) == self.identity and
            base._signature(self.group_fd) == self.group_signature and
            self.tasks_fd is not None and
            base._signature(self.tasks_fd) == self.tasks_signature and
            all(base._signature(fd) == self.signatures[name]
                for name, fd in self.task_fds.items()), 'exit-owner-changed')

    def close(self):
        if self.closed:
            return
        self.closed = True
        error = None
        for descriptor in [*self.task_fds.values(), self.tasks_fd, self.group_fd]:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as fault:
                    error = fault
        self.task_fds.clear()
        if error is not None:
            raise error


class MmDetachedObservation(base.ExitOnlyObservation):
    def __init__(self, sample, initial_leader, missing_sample_ns):
        base._require(type(sample) is _BeforeStatusSample and not sample.closed
            and initial_leader is sample.fields and missing_sample_ns == sample.sample_started_ns
            and sample.before and sample.frontier_completed_ns <= missing_sample_ns,
            'exit-mm-same-sample-capability')
        self.prior = dict(sample.before)
        self.prior_completed_ns = sample.frontier_completed_ns
        self.original_leader_state = initial_leader['State'][0]
        sample._held()
        super().__init__(sample.pid, sample.held_pidfd, sample.owner_token,
                         initial_leader, missing_sample_ns)
        try:
            sample._held()
            base._require(self.identity == sample.identity and self.names == sample.names
                and self.held_signature == sample.held_signature
                and self.group_signature == sample.group_signature
                and self.tasks_signature == sample.tasks_signature
                and self.task_signatures == sample.signatures,
                'exit-mm-capture-identity')
        except BaseException:
            self.close()
            raise

    def _leader_state(self, status_state, stat_state=None):
        base._require(status_state in 'RSDZ' and
            (stat_state is None or stat_state in 'RSDZ'), 'exit-mm-leader-state')

    def recheck(self):
        record = super().recheck()
        base._require(self.starts == {name: row['starttime'] for name, row in self.prior.items()}
            and all(_exiting(row) for row in self.prior.values()), 'exit-mm-prior-starttime')
        record.update(profile=PROFILE, original_leader_state=self.original_leader_state,
            prior_stat_frontier=self.prior, prior_frontier_completed_ns=self.prior_completed_ns,
            resource_release_authorized=False, arbitrary_process_descendants_closed=False)
        return record
