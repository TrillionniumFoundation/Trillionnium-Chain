"""V4 worker retirement needs a previously bound kernel thread-pidfd event.

The unchanged full V2 classification precedes binding. A worker disappearing
mid-frontier permits only bounded recapture of two complete remaining frontiers,
never zero RSS, resource release or success without the original owned wait4.
Linux v7.0 delays early-leader pidfd readiness; the leader always needs procfs.
"""
import errno
import os
import select
import time

import llm_runtime_exit_observation as base

PROFILE = 'linux-owned-exit-worker-pidfd-v4'
MAX_DRAIN_NS = base.MAX_DRAIN_NS
# Official Linux v7.0 include/uapi/linux/pidfd.h; never fall back to flags=0.
PIDFD_THREAD = os.O_EXCL


class _Recapture(Exception):
    """Only a newly proved original worker retirement can request recapture."""


class WorkerPidfdObservation(base.ExitOnlyObservation):
    def __init__(self, pid, held_pidfd, owner_token, initial_leader, missing_sample_ns):
        self.baseline_qualified = self.failed = False
        self.thread_fds, self.thread_signatures, self.bindings = {}, {}, {}
        self.active_names, self.pending_retired = (), ()
        self.retirements, self.baseline_starts = {}, {}
        self.failure_context = None
        super().__init__(pid, held_pidfd, owner_token, initial_leader, missing_sample_ns)

    def _owner(self):
        base._require(not self.closed and
            base._signature(self.held_pidfd) == self.held_signature and
            base._signature(self.group_fd) == self.group_signature and
            base._signature(self.tasks_fd) == self.tasks_signature and
            base._pidfd_identity(self.pid, self.held_pidfd) == self.identity,
            'exit-owner-changed')
        for name, descriptor in self.task_fds.items():
            base._require(base._signature(descriptor) == self.task_signatures[name],
                          'exit-task-fd-reused')
        for name, descriptor in self.thread_fds.items():
            # After kernel reap fdinfo may say -1. The retained FD still names
            # its original task; never rebind it from a later numeric identity.
            base._require(base._signature(descriptor) == self.thread_signatures[name],
                          'exit-worker-pidfd-reused')

    def _deadline(self):
        base._require(time.monotonic_ns() < self.sample_started_ns + MAX_DRAIN_NS,
                      'exit-worker-deadline')

    def _fields(self, name, count, shrinking):
        # Validate each successful read before a later read can disappear.
        if self.failure_context is not None:
            self.failure_context.update(reading_task=name, reading_component='status')
        fields = base._status(base._read(self.task_fds[name], 'status'))
        namespace = tuple(base._namespace(fields, 'NSpid'))
        base._require(base._one(fields, 'Pid') == int(name) and
            base._one(fields, 'Tgid') == self.visible and
            base._one(fields, 'PPid') == self.parent and
            base._one(fields, 'Threads') == count and
            tuple(base._namespace(fields, 'NStgid')) == self.namespace and
            namespace[0] == int(name) and len(namespace) == len(self.namespace),
            'exit-task-identity')
        base._require(len(fields['State'][0]) == 1 and
            fields['State'][0] in 'RSDTtXZPI' and 'VmRSS' not in fields,
            'exit-task-not-exit-only')
        if name in self.bindings:
            base._require(namespace == self.bindings[name]['namespace'], 'exit-task-namespace')
        if int(name) == self.visible or shrinking:
            base._require(fields['State'][0] == 'Z', 'exit-worker-remaining-not-zombie')
        if self.failure_context is not None:
            self.failure_context['reading_component'] = 'stat'
        observed = base._stat(base._read(self.task_fds[name], 'stat'))
        base._require(observed['pid'] == int(name) and observed['ppid'] == self.parent and
            observed['flags'] & base.PF_EXITING and not observed['flags'] & base.PF_KTHREAD and
            observed['vsize'] == observed['rss'] == 0, 'exit-task-not-exit-only')
        base._require(observed['starttime'] == self.baseline_starts[name], 'exit-task-starttime')
        if int(name) == self.visible or shrinking:
            base._require(observed['state'] == 'Z', 'exit-worker-remaining-not-zombie')
        return namespace, observed

    def _bind_workers(self):
        base._require(callable(getattr(os, 'pidfd_open', None)), 'exit-worker-pidfd-unavailable')
        parent = base._proc_fields(base.Path('/proc/self/status'))
        parent_namespace = base._namespace(parent, 'NSpid')
        base._require(parent_namespace[0] == base._one(parent, 'Pid') and
            parent_namespace[-1] == os.getpid(), 'exit-parent')
        coordinate = len(parent_namespace) - 1
        for name in self.names:
            if int(name) == self.visible:
                continue
            namespace, observed = self._fields(name, len(self.names), False)
            base._require(len(namespace) > coordinate, 'exit-worker-pidfd-binding')
            descriptor = os.pidfd_open(namespace[coordinate], PIDFD_THREAD)
            self.thread_fds[name] = descriptor
            self.thread_signatures[name] = base._signature(descriptor)
            identity = base._proc_fields(base.Path(f'/proc/self/fdinfo/{descriptor}'))
            base._require(base._one(identity, 'Pid') == int(name) and
                tuple(base._namespace(identity, 'NSpid')) == namespace,
                'exit-worker-pidfd-binding')
            repeated, repeated_stat = self._fields(name, len(self.names), False)
            repeated_identity = base._proc_fields(base.Path(f'/proc/self/fdinfo/{descriptor}'))
            base._require(repeated == namespace and
                repeated_stat['starttime'] == observed['starttime'] and
                base._one(repeated_identity, 'Pid') == int(name) and
                tuple(base._namespace(repeated_identity, 'NSpid')) == namespace,
                'exit-worker-pidfd-binding')
            self.bindings[name] = dict(namespace=namespace,
                starttime=observed['starttime'], local_tid=namespace[coordinate])
        self._owner()

    def _check_bindings(self):
        for name, descriptor in self.thread_fds.items():
            namespace, _ = self._fields(name, len(self.names), False)
            identity = base._proc_fields(base.Path(f'/proc/self/fdinfo/{descriptor}'))
            base._require(namespace == self.bindings[name]['namespace'] and
                base._one(identity, 'Pid') == int(name) and
                tuple(base._namespace(identity, 'NSpid')) == namespace,
                'exit-worker-pidfd-binding')
        self._owner()

    def _retire(self, name, candidate, error_errno=None):
        base._require(self.baseline_qualified and name in self.bindings and
            name in self.active_names and name not in candidate and
            int(name) != self.visible, 'exit-worker-retirement-ineligible')
        self._owner()
        descriptor = self.thread_fds[name]
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        events = poller.poll(0)
        allowed = select.POLLIN | select.POLLHUP
        base._require(len(events) == 1 and events[0][0] == descriptor and
            events[0][1] & select.POLLIN and not events[0][1] & ~allowed,
            'exit-worker-terminal-event-unavailable')
        self._owner()
        candidate[name] = dict(terminal_observed_ns=time.monotonic_ns(),
            revents=events[0][1], original_starttime=self.bindings[name]['starttime'],
            original_namespace=list(self.bindings[name]['namespace']),
            read_errno=error_errno, scope='worker kernel terminal event; not physical RSS release')
        self.failure_context['candidate_retirements'] = dict(candidate)

    def _names(self, candidate):
        count = self._leader(base._status(base._read(self.group_fd, 'status')))
        names = base._task_names(self.tasks_fd)
        self.failure_context.update(reported_threads=count, observed_tasks=list(names))
        base._require(str(self.visible) in names and set(names) <= set(self.active_names) and
            not set(names) & set(candidate), 'exit-worker-task-set')
        for name in self.active_names:
            if name not in names and name not in candidate:
                self._retire(name, candidate)
        base._require(count == len(names), 'exit-worker-frontier-change')
        return names, count

    def _worker_frontier(self, candidate):
        names, count = self._names(candidate)
        shrinking = bool(candidate)
        result = {}
        for name in names:
            try:
                _, result[name] = self._fields(name, count, shrinking)
            except OSError as error:
                if error.errno not in (errno.ENOENT, errno.ESRCH):
                    raise
                # A leader read failure or unbound worker can never authorize this.
                self._retire(name, candidate, error.errno)
                raise _Recapture from error
        after, after_count = self._names(candidate)
        if after != names:
            base._require(set(after) < set(names), 'exit-worker-frontier-change')
            raise _Recapture
        base._require(after_count == count, 'exit-worker-frontier-change')
        return names, result

    def recheck(self):
        base._require(not self.failed, 'exit-worker-sticky-failure')
        try:
            if not self.baseline_qualified:
                base.ExitOnlyObservation.recheck(self)
                self.baseline_starts = dict(self.starts)
                self.active_names = self.names
                self._bind_workers()
                # Acquisition cannot erase even one task or change its qualification.
                base.ExitOnlyObservation.recheck(self)
                self._check_bindings()
                self._deadline()
                self.baseline_qualified = True
                self.record.update(profile=PROFILE, initial_tasks=list(self.names),
                    pending_retired_tasks=[], worker_bindings=self._binding_record(),
                    transition='complete-initial-set-with-held-worker-pidfds')
                return self.record
            self._owner()
            candidate = dict(self.retirements)
            self.failure_context = dict(source='same-v4-frontier-call', diagnostic_only=True,
                candidate_retirements=dict(candidate), interrupted_frontiers=[])
            # Each recapture consumes a newly proved original worker; never an open retry.
            for _ in range(base.MAX_TASKS):
                self._deadline()
                preceding = len(candidate)
                try:
                    before_names, before = self._worker_frontier(candidate)
                    after_names, after = self._worker_frontier(candidate)
                    if before_names != after_names:
                        raise _Recapture
                except _Recapture as error:
                    base._require(len(candidate) > preceding and
                        len(candidate) <= len(self.names)-1, 'exit-worker-recapture-bound')
                    self.failure_context['interrupted_frontiers'].append(dict(
                        monotonic_ns=time.monotonic_ns(), retired_tasks=list(candidate),
                        error_errno=getattr(error.__cause__, 'errno', None),
                        reading_task=self.failure_context.get('reading_task'),
                        reading_component=self.failure_context.get('reading_component'),
                        observed_tasks=self.failure_context.get('observed_tasks')))
                    continue
                self._owner()
                self._deadline()
                self.active_names, self.retirements = before_names, candidate
                self.pending_retired = tuple(name for name in self.names if name in candidate)
                self.record = dict(profile=PROFILE, sample_started_ns=self.sample_started_ns,
                    classification_completed_ns=time.monotonic_ns(), initial_tasks=list(self.names),
                    tasks=list(before_names), pending_retired_tasks=list(self.pending_retired),
                    worker_terminal_events=dict(candidate), worker_bindings=self._binding_record(),
                    interrupted_frontiers=self.failure_context['interrupted_frontiers'],
                    frontier_before=before, frontier_after=after,
                    transition='worker-terminal-pending-group-wait4' if candidate else 'stable-initial-set',
                    scope='only exact owned-child terminal wait4 can close; not zero or released RSS')
                self.failure_context = None
                return self.record
            raise base.ExitObservationError('exit-worker-recapture-bound')
        except BaseException:
            self.failed = True
            raise

    def _binding_record(self):
        return {name: dict(namespace=list(value['namespace']), starttime=value['starttime'],
            local_tid=value['local_tid'], pidfd_signature=list(self.thread_signatures[name]))
            for name, value in self.bindings.items()}

    def belongs_to(self, pid, held_pidfd, owner_token):
        if not self.baseline_qualified or self.failed:
            return False
        try:
            self._owner()
            return super().belongs_to(pid, held_pidfd, owner_token)
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def close(self):
        error = None
        for descriptor in self.thread_fds.values():
            try:
                os.close(descriptor)
            except OSError as fault:
                error = fault
        self.thread_fds.clear()
        try:
            super().close()
        finally:
            if error is not None:
                raise error
