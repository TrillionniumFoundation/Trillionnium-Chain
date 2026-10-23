"""V3 terminal-only task subsets; disappearing tasks stay pending until wait4.

The complete initial V2 observation is mandatory. A later stable strict subset
is not evidence that missing tasks died or released memory. It permits only the
same original bounded terminal wait, retaining every original descriptor and
reservation. Unknown observations are sticky and cannot be erased by shrinkage.
"""
import time

import llm_runtime_exit_observation as base

PROFILE = 'linux-owned-exit-terminal-subset-v3'
MAX_DRAIN_NS = base.MAX_DRAIN_NS


class TerminalSubsetObservation(base.ExitOnlyObservation):
    """Held-owner observation, never constructible from a diagnostic dictionary."""

    def __init__(self, pid, held_pidfd, owner_token, initial_leader, missing_sample_ns):
        self.baseline_qualified = False
        self.failed = False
        self.active_names = ()
        self.baseline_starts = {}
        self.pending_retired = ()
        self.failure_context = None
        super().__init__(pid, held_pidfd, owner_token, initial_leader, missing_sample_ns)

    def _owner(self):
        base._require(not self.closed and
            base._signature(self.held_pidfd) == self.held_signature and
            base._signature(self.group_fd) == self.group_signature and
            base._signature(self.tasks_fd) == self.tasks_signature and
            base._pidfd_identity(self.pid, self.held_pidfd) == self.identity,
            'exit-owner-changed')

    def _subset_frontier(self):
        count = self._leader(base._status(base._read(self.group_fd, 'status')))
        names = base._task_names(self.tasks_fd)
        self.failure_context = dict(source='same-v3-frontier-call',
            reported_threads=count, observed_tasks=list(names), diagnostic_only=True)
        base._require(str(self.visible) in names and count == len(names) and
            set(names) <= set(self.active_names), 'exit-subset-task-set')
        shrinking = names != self.active_names or bool(self.pending_retired)
        result = {}
        # Original FDs and identities remain retained, including pending tasks.
        for name, descriptor in self.task_fds.items():
            base._require(base._signature(descriptor) == self.task_signatures[name],
                          'exit-task-fd-reused')
        for name in names:
            descriptor = self.task_fds[name]
            fields = base._status(base._read(descriptor, 'status'))
            observed = base._stat(base._read(descriptor, 'stat'))
            base._require(base._one(fields, 'Pid') == int(name) and
                base._one(fields, 'Tgid') == self.visible and
                base._one(fields, 'PPid') == self.parent and
                base._one(fields, 'Threads') == count and
                tuple(base._namespace(fields, 'NStgid')) == self.namespace,
                'exit-task-identity')
            namespace = base._namespace(fields, 'NSpid')
            base._require(namespace[0] == int(name) and len(namespace) == len(self.namespace),
                          'exit-task-namespace')
            base._require(len(fields['State'][0]) == 1 and
                fields['State'][0] in 'RSDTtXZPI' and 'VmRSS' not in fields and
                observed['pid'] == int(name) and observed['ppid'] == self.parent and
                observed['flags'] & base.PF_EXITING and
                not observed['flags'] & base.PF_KTHREAD and
                observed['vsize'] == 0 and observed['rss'] == 0,
                'exit-task-not-exit-only')
            base._require(observed['starttime'] == self.baseline_starts[name],
                          'exit-task-starttime')
            if int(name) == self.visible or shrinking:
                base._require(fields['State'][0] == observed['state'] == 'Z',
                              'exit-subset-remaining-not-zombie')
            result[name] = observed
        after = base._task_names(self.tasks_fd)
        after_count = self._leader(base._status(base._read(self.group_fd, 'status')))
        self.failure_context.update(observed_tasks_after=list(after),
                                    reported_threads_after=after_count)
        base._require(after == names and after_count == count, 'exit-subset-frontier-change')
        return names, result

    def recheck(self):
        base._require(not self.failed, 'exit-subset-sticky-failure')
        try:
            if not self.baseline_qualified:
                # No shrinkage is eligible before every original task has
                # passed the unchanged complete V2 double frontier.
                super().recheck()
                self.active_names = self.names
                self.baseline_starts = dict(self.starts)
                self.baseline_qualified = True
                self.record.update(profile=PROFILE, initial_tasks=list(self.names),
                    pending_retired_tasks=[], transition='complete-initial-set')
                return self.record
            self._owner()
            before_names, before = self._subset_frontier()
            after_names, after = self._subset_frontier()
            base._require(before_names == after_names, 'exit-subset-frontier-change')
            self._owner()
            # Commit only after both complete frontiers and owner checks.
            self.active_names = before_names
            self.pending_retired = tuple(name for name in self.names if name not in before_names)
            self.record = dict(profile=PROFILE, sample_started_ns=self.sample_started_ns,
                classification_completed_ns=time.monotonic_ns(), initial_tasks=list(self.names),
                tasks=list(before_names), pending_retired_tasks=list(self.pending_retired),
                frontier_before=before, frontier_after=after,
                transition='pending-terminal-subset' if self.pending_retired else 'stable-initial-set',
                scope='pending task retirement; only exact owned-child terminal wait4 can close it; not zero or released RSS')
            self.failure_context = None
            return self.record
        except BaseException:
            self.failed = True
            raise

    def belongs_to(self, pid, held_pidfd, owner_token):
        return (self.baseline_qualified and not self.failed and
                super().belongs_to(pid, held_pidfd, owner_token))
