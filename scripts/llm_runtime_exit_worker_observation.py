"""V4 worker retirement needs a previously bound kernel thread-pidfd event.

A separate source-bound initial-capture state may retain an owned reservation
across disappearing tasks. It is not a complete exit-only classification: only
the original timed wait4 and resource receipt may close it. Complete initial V2
classification still precedes worker-pidfd binding and later retirement proof.
If a proved original worker vanishes during binding, a separate pending state
retains that complete prebinding proof and every partial capability. It still
requires the original timed owned wait4; missing pidfd/leader reads never qualify.
A held task read's ESRCH is eligible only after all original worker bindings,
with that worker's retained pidfd terminal event and no other roster loss.
No state measures zero RSS or physical release. The leader always needs procfs.
"""
import contextvars
import errno
import os
import select
import sys
import time

import llm_runtime_exit_observation as base

PROFILE = 'linux-owned-exit-worker-pidfd-v4'
MAX_DRAIN_NS = base.MAX_DRAIN_NS
# Official Linux v7.0 include/uapi/linux/pidfd.h; never fall back to flags=0.
PIDFD_THREAD = os.O_EXCL


class _Recapture(Exception):
    """Only a newly proved original worker retirement can request recapture."""


class _CountDecreased(Exception):
    """A fully checked task read needs a new held-worker retirement proof."""
    def __init__(self, reported_threads):
        self.reported_threads = reported_threads


class _InitialTerminalPending:
    """Private acquisition state; no serialized record can construct authority."""
    def __init__(self, names, count):
        self.names = self.active_names = names
        self.count = self.initial_count = count
        self.pending = False
        self.retired, self.statuses, self.validated = set(), {}, {}
        self.interruptions = []


class _BindingTaskMissing(Exception):
    """Only a proved original task's held-directory read may raise this."""
    def __init__(self, task, component, phase, error_errno, terminal_event=None):
        self.task, self.component, self.phase = task, component, phase
        self.error_errno = error_errno
        self.terminal_event = terminal_event


class _BindingTerminalPending:
    """Incomplete acquisition; never group completion or resource evidence."""
    def __init__(self, interruption, prebinding_record, terminal_event=None):
        self.interruption, self.prebinding_record = interruption, prebinding_record
        self.terminal_event = terminal_event


class WorkerPidfdObservation(base.ExitOnlyObservation):
    def __init__(self, pid, held_pidfd, owner_token, initial_leader, missing_sample_ns):
        self.baseline_qualified = self.failed = False
        self.thread_fds, self.thread_signatures, self.bindings = {}, {}, {}
        self.active_names, self.pending_retired = (), ()
        self.retirements, self.baseline_starts = {}, {}
        self.failure_context = None
        self.initial_capture = None
        self.prebinding_record = self.binding_pending = None
        self.acquisition_phase = 'owner-context'
        # Keep the original owner/acquisition predicates, but retain a typed
        # pending result when a nonleader disappears before a complete baseline.
        # V2/V3 and the model-bound pilot source remain byte-for-byte unchanged.
        self.pid, self.held_pidfd, self.owner_token = pid, held_pidfd, owner_token
        self.group_fd, self.tasks_fd, self.task_fds = None, None, {}
        self.task_signatures, self.starts = {}, {}
        self.closed, self.record = False, {}
        self.sample_started_ns = missing_sample_ns
        try:
            base._require(type(pid) is int and pid > 0 and type(held_pidfd) is int and held_pidfd >= 0 and
                owner_token is not None and type(missing_sample_ns) is int and
                0 < missing_sample_ns <= time.monotonic_ns(), 'exit-owner-context')
            self.held_signature = base._signature(held_pidfd)
            self.identity = base._pidfd_identity(pid, held_pidfd)
            self.visible, self.parent, self.namespace = self.identity
            count = self._leader(initial_leader)
            self._deadline()
            self.acquisition_phase = 'group-directory-open'
            self.group_fd = base._open_group(self.visible)
            self.group_signature = base._signature(self.group_fd)
            self.tasks_fd = os.open('task', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=self.group_fd)
            self.tasks_signature = base._signature(self.tasks_fd)
            self.names = base._task_names(self.tasks_fd)
            base._require(str(self.visible) in self.names, 'exit-leader-not-in-task-set')
            base._require(len(self.names) <= count, 'exit-task-set')
            self.initial_capture = _InitialTerminalPending(self.names, count)
            if len(self.names) < count:
                self._initial_interruption(None, 'initial-roster', count=count, names=self.names)
            self.acquisition_phase = 'task-directory-open'
            for name in self.names:
                try:
                    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                        dir_fd=self.tasks_fd)
                except OSError as error:
                    self._initial_missing(name, 'open', error)
                    continue
                self.task_fds[name] = descriptor
                self.task_signatures[name] = base._signature(descriptor)
            self.recheck()
        except BaseException as error:
            self.failed = True
            try:
                self.close()
            finally:
                self._retain_constructor_refusal(error)
            raise

    def _retain_constructor_refusal(self, error):
        # The existing supervisor rejects an exact typed failed result before
        # its immediate-terminal race branch. Preserve that rejection even when
        # current_rss catches the constructor exception. This slot only refuses;
        # it cannot authorize execution. The pilot can run as __main__ or import.
        expected = base.Path(__file__).with_name('llm_runtime_pilot.py').resolve()
        for name in ('__main__', 'llm_runtime_pilot'):
            module = sys.modules.get(name)
            source = getattr(module, '__file__', None)
            if type(source) is not str or base.Path(source).resolve() != expected:
                continue
            context = getattr(module, '_RSS_OWNER_CONTEXT', None)
            selected = getattr(module, '_RSS_EXIT_CLASS', None)
            output = getattr(module, '_RSS_EXIT_OBSERVATION', None)
            if not all(type(value) is contextvars.ContextVar for value in (context, selected, output)):
                continue
            owner = context.get()
            if (type(owner) is tuple and len(owner) == 3 and owner[0] == self.pid and
                    owner[1] == self.held_pidfd and owner[2] is self.owner_token and
                    selected.get() is type(self) is WorkerPidfdObservation and output.get() is None):
                output.set(self)
                trace = getattr(module, '_RSS_READ_TRACE', None)
                if type(trace) is contextvars.ContextVar and type(trace.get()) is dict:
                    # Fixed source frames from this original failing call, not
                    # a later proc snapshot or a diagnostic grant of authority.
                    frames, cursor, scanned = [], error.__traceback__, 0
                    sources = {str(base.Path(__file__).resolve()),
                               str(base.Path(base.__file__).resolve())}
                    while cursor is not None and len(frames) < 16 and scanned < 32:
                        scanned += 1
                        code = cursor.tb_frame.f_code
                        if str(base.Path(code.co_filename).resolve()) in sources:
                            frames.append(dict(function=code.co_name, line=cursor.tb_lineno))
                        cursor = cursor.tb_next
                    trace.get().setdefault('same_sample_exit_acquisition_failure', dict(
                        source='original-constructor-exception', phase=self.acquisition_phase,
                        error_type=type(error).__name__, error_errno=getattr(error, 'errno', None),
                        source_frames=frames, diagnostic_only=True))

    def _initial_interruption(self, name, component, *, error_errno=None, count=None, names=None):
        capture = self.initial_capture
        capture.pending = True
        if name is not None:
            base._require(name in capture.names and int(name) != self.visible,
                          'exit-worker-initial-leader-loss')
            capture.retired.add(name)
        base._require(len(capture.interruptions) < 2 * base.MAX_TASKS,
                      'exit-worker-initial-capture-bound')
        capture.interruptions.append(dict(task=name, component=component, error_errno=error_errno,
            reported_threads=count, observed_tasks=list(names) if names is not None else None,
            observed_ns=time.monotonic_ns()))

    def _initial_missing(self, name, component, error):
        if error.errno not in (errno.ENOENT, errno.ESRCH) or int(name) == self.visible:
            raise error
        self._initial_interruption(name, component, error_errno=error.errno)

    def _initial_names(self):
        capture = self.initial_capture
        count = self._leader(base._status(base._read(self.group_fd, 'status')))
        names = base._task_names(self.tasks_fd)
        base._require(count <= capture.count and str(self.visible) in names and
            set(names) <= set(capture.active_names) and not set(names) & capture.retired,
            'exit-worker-initial-task-set')
        if names != capture.active_names or count != capture.count or count != len(names):
            self._initial_interruption(None, 'task-set', count=count, names=names)
        capture.retired.update(set(capture.active_names) - set(names))
        capture.active_names, capture.count = names, count
        return names, count

    def _initial_fields(self, name, count):
        capture = self.initial_capture
        descriptor = self.task_fds[name]
        base._require(base._signature(descriptor) == self.task_signatures[name], 'exit-task-fd-reused')
        try:
            fields = base._status(base._read(descriptor, 'status'))
        except OSError as error:
            self._initial_missing(name, 'status', error)
            return None
        # Every successful status is checked before the next read can vanish.
        namespace = tuple(base._namespace(fields, 'NSpid'))
        base._require(base._one(fields, 'Pid') == int(name) and
            base._one(fields, 'Tgid') == self.visible and base._one(fields, 'PPid') == self.parent and
            tuple(base._namespace(fields, 'NStgid')) == self.namespace and
            namespace[0] == int(name) and len(namespace) == len(self.namespace), 'exit-task-identity')
        reported = base._one(fields, 'Threads')
        base._require(reported <= min(count, capture.count), 'exit-task-identity')
        base._require(len(fields['State'][0]) == 1 and fields['State'][0] in 'RSDTtXZPI' and
            'VmRSS' not in fields, 'exit-task-not-exit-only')
        if int(name) == self.visible:
            base._require(fields['State'][0] == 'Z', 'exit-leader-state')
        previous = capture.statuses.get(name)
        base._require(previous is None or previous['namespace'] == namespace, 'exit-task-namespace')
        capture.statuses[name] = dict(namespace=namespace, state=fields['State'][0], reported_threads=reported)
        if reported < capture.count:
            self._initial_interruption(None, 'task-status-count', count=reported)
            capture.count = reported
        try:
            observed = base._stat(base._read(descriptor, 'stat'))
        except OSError as error:
            self._initial_missing(name, 'stat', error)
            return None
        base._require(observed['pid'] == int(name) and observed['ppid'] == self.parent and
            observed['flags'] & base.PF_EXITING and not observed['flags'] & base.PF_KTHREAD and
            observed['vsize'] == observed['rss'] == 0, 'exit-task-not-exit-only')
        if int(name) == self.visible:
            base._require(observed['state'] == 'Z', 'exit-leader-state')
        previous = capture.validated.get(name)
        base._require(previous is None or previous['starttime'] == observed['starttime'], 'exit-task-starttime')
        capture.validated[name] = observed
        return observed

    def _initial_frontier(self):
        self._owner()
        self._deadline()
        names, count = self._initial_names()
        result = {}
        for name in names:
            observed = self._initial_fields(name, count)
            if observed is not None:
                result[name] = observed
        self._initial_names()
        self._owner()
        self._deadline()
        return result

    def _initial_record(self):
        capture = self.initial_capture
        self.pending_retired = tuple(name for name in self.names if name in capture.retired)
        self.record = dict(schema='llm-owned-initial-terminal-pending-v1', profile=PROFILE,
            sample_started_ns=self.sample_started_ns, observed_ns=time.monotonic_ns(),
            initial_threads=capture.initial_count, initial_tasks=list(self.names),
            tasks=list(capture.active_names), pending_retired_tasks=list(self.pending_retired),
            validated_statuses=dict(capture.statuses), validated_tasks=dict(capture.validated),
            validated_tasks_scope='cumulative successful reads; not a complete same-call frontier',
            interruptions=list(capture.interruptions), complete_initial_classification=False,
            transition='initial-capture-pending-owned-wait4',
            scope='reservation retained; only original timed owned wait4 and resource receipt can close; not zero RSS')
        return self.record

    def _held_capabilities(self):
        base._require(not self.closed and
            base._signature(self.held_pidfd) == self.held_signature and
            base._signature(self.group_fd) == self.group_signature and
            base._signature(self.tasks_fd) == self.tasks_signature,
            'exit-owner-changed')
        for name, descriptor in self.task_fds.items():
            base._require(base._signature(descriptor) == self.task_signatures[name],
                          'exit-task-fd-reused')
        for name, descriptor in self.thread_fds.items():
            # After kernel reap fdinfo may say -1. The retained FD still names
            # its original task; never rebind it from a later numeric identity.
            base._require(base._signature(descriptor) == self.thread_signatures[name],
                          'exit-worker-pidfd-reused')

    def _owner(self):
        self._held_capabilities()
        base._require(base._pidfd_identity(self.pid, self.held_pidfd) == self.identity,
                      'exit-owner-changed')

    def _deadline(self):
        base._require(time.monotonic_ns() < self.sample_started_ns + MAX_DRAIN_NS,
                      'exit-worker-deadline')

    def _postbinding_terminal_event(self, name):
        # Nomination by ESRCH grants nothing. Every original worker must already
        # have completed its real binding; this one retained pidfd must now
        # positively prove termination. The incomplete frontier stays pending.
        expected = set(self.names) - {str(self.visible)}
        base._require(not self.failed and not self.baseline_qualified and
            self.prebinding_record is not None and not self.initial_capture.pending and
            self.acquisition_phase in ('post-bind-double-frontier', 'worker-pidfd-recheck') and
            name in expected and set(self.bindings) == set(self.thread_fds) ==
            set(self.thread_signatures) == expected and
            set(self.task_fds) == set(self.task_signatures) == set(self.names),
            'exit-worker-retirement-ineligible')
        for task in expected:
            binding = self.bindings[task]
            base._require(binding['namespace'] == self.initial_capture.statuses[task]['namespace'] and
                binding['starttime'] == self.baseline_starts[task] ==
                self.initial_capture.validated[task]['starttime'], 'exit-worker-pidfd-binding')
        self._owner()
        self._deadline()
        descriptor = self.thread_fds[name]
        poller = select.poll()
        poller.register(descriptor, select.POLLIN)
        events = poller.poll(0)
        allowed = select.POLLIN | select.POLLHUP
        base._require(len(events) == 1 and events[0][0] == descriptor and
            events[0][1] & select.POLLIN and not events[0][1] & ~allowed,
            'exit-worker-terminal-event-unavailable')
        self._owner()
        self._deadline()
        return dict(task=name, terminal_observed_ns=time.monotonic_ns(), revents=events[0][1],
            original_starttime=self.bindings[name]['starttime'],
            original_namespace=list(self.bindings[name]['namespace']), read_errno=errno.ESRCH,
            scope='this original bound worker terminal event; not a complete frontier, group exit or RSS release')

    def _task_read(self, name, component):
        acquiring = (self.prebinding_record is not None and not self.baseline_qualified and
            self.acquisition_phase in ('worker-pidfd-bind', 'post-bind-double-frontier',
                                       'worker-pidfd-recheck'))
        if acquiring:
            base._require(base._signature(self.task_fds[name]) == self.task_signatures[name],
                          'exit-task-fd-reused')
        try:
            return base._read(self.task_fds[name], component)
        except OSError as error:
            if acquiring and error.errno == errno.ENOENT and int(name) != self.visible:
                raise _BindingTaskMissing(name, component, self.acquisition_phase, error.errno) from error
            if (acquiring and error.errno == errno.ESRCH and int(name) != self.visible and
                    self.acquisition_phase in ('post-bind-double-frontier', 'worker-pidfd-recheck')):
                event = self._postbinding_terminal_event(name)
                raise _BindingTaskMissing(name, component, self.acquisition_phase, error.errno, event) from error
            raise

    def _fields(self, name, count, shrinking):
        # Validate each successful read before a later read can disappear.
        if self.failure_context is not None:
            self.failure_context.update(reading_task=name, reading_component='status')
        fields = base._status(self._task_read(name, 'status'))
        namespace = tuple(base._namespace(fields, 'NSpid'))
        base._require(base._one(fields, 'Pid') == int(name) and
            base._one(fields, 'Tgid') == self.visible and
            base._one(fields, 'PPid') == self.parent and
            tuple(base._namespace(fields, 'NStgid')) == self.namespace and
            namespace[0] == int(name) and len(namespace) == len(self.namespace),
            'exit-task-identity')
        reported_threads = base._one(fields, 'Threads')
        decreased = self.baseline_qualified and 0 < reported_threads < count
        base._require(reported_threads == count or decreased, 'exit-task-identity')
        base._require(len(fields['State'][0]) == 1 and
            fields['State'][0] in 'RSDTtXZPI' and 'VmRSS' not in fields,
            'exit-task-not-exit-only')
        if name in self.bindings:
            base._require(namespace == self.bindings[name]['namespace'], 'exit-task-namespace')
        if self.prebinding_record is not None and not self.baseline_qualified:
            base._require(namespace == self.initial_capture.statuses[name]['namespace'],
                          'exit-task-namespace')
        if int(name) == self.visible or shrinking:
            base._require(fields['State'][0] == 'Z', 'exit-worker-remaining-not-zombie')
        if self.failure_context is not None:
            self.failure_context['reading_component'] = 'stat'
        try:
            raw_stat = self._task_read(name, 'stat')
        except OSError:
            # A changed count needs the complete task read before recapture.
            # A later ENOENT cannot erase an inconsistent reported count.
            base._require(not decreased, 'exit-worker-frontier-change')
            raise
        observed = base._stat(raw_stat)
        base._require(observed['pid'] == int(name) and observed['ppid'] == self.parent and
            observed['flags'] & base.PF_EXITING and not observed['flags'] & base.PF_KTHREAD and
            observed['vsize'] == observed['rss'] == 0, 'exit-task-not-exit-only')
        base._require(observed['starttime'] == self.baseline_starts[name], 'exit-task-starttime')
        if int(name) == self.visible or shrinking:
            base._require(observed['state'] == 'Z', 'exit-worker-remaining-not-zombie')
        if decreased:
            # Do not discard any observed bad identity, memory, state or stat.
            # This complete task read is still not a complete frontier.
            raise _CountDecreased(reported_threads)
        return namespace, observed

    def _frontier(self):
        if self.prebinding_record is None or self.baseline_qualified:
            return super()._frontier()
        # Preserve the original complete roster/count, two-frontier and birth
        # requirements. Validate each status BEFORE a later stat can vanish.
        # The unchanged V2/V3 implementations never take this V4-only path.
        count = self._leader(base._status(base._read(self.group_fd, 'status')))
        base._require(base._task_names(self.tasks_fd) == self.names and
                      count == len(self.names), 'exit-task-set')
        result = {}
        for name in self.names:
            _, result[name] = self._fields(name, count, False)
        base._require(base._task_names(self.tasks_fd) == self.names and
            self._leader(base._status(base._read(self.group_fd, 'status'))) == count,
            'exit-task-set')
        return result

    def _retain_binding_task_loss(self, error):
        base._require(type(error) is _BindingTaskMissing and self.prebinding_record is not None and
            not self.baseline_qualified and error.task in self.names and
            int(error.task) != self.visible, 'exit-worker-pidfd-binding')
        self._owner()
        self._deadline()
        names, _ = self._initial_names()
        # ENOENT alone is insufficient: the same owned roster must now have
        # actually lost this original nonleader, without additions or revival.
        base._require(error.task not in names and error.task in self.initial_capture.retired,
                      'exit-worker-frontier-change')
        if error.terminal_event is not None:
            self._postbinding_roster(error.task)
        self._initial_interruption(error.task, 'binding-' + error.component,
                                   error_errno=error.error_errno)
        self._initial_frontier()
        if error.terminal_event is not None:
            self._postbinding_roster(error.task)
        self.binding_pending = _BindingTerminalPending(dict(task=error.task,
            component=error.component, phase=error.phase, error_errno=error.error_errno),
            self.prebinding_record, error.terminal_event)
        self.acquisition_phase = 'binding-terminal-pending'
        return self._binding_pending_record()

    def _postbinding_roster(self, task):
        # This narrow transition proves only one newly missing worker, even if
        # the original group had more. Other losses need their own evidence.
        capture = self.initial_capture
        expected = tuple(name for name in self.names if name != task)
        base._require(capture.active_names == expected and capture.retired == {task} and
                      capture.count == len(expected), 'exit-worker-frontier-change')

    def _binding_pending_record(self):
        base._require(type(self.binding_pending) is _BindingTerminalPending,
                      'exit-worker-pidfd-binding')
        record = self._initial_record()
        record.update(schema='llm-owned-binding-terminal-pending-v1',
            transition='binding-acquisition-pending-owned-wait4',
            complete_prebinding_classification=True, complete_worker_pidfd_acquisition=False,
            prebinding_classification=self.binding_pending.prebinding_record,
            acquisition_interruption=dict(self.binding_pending.interruption),
            complete_worker_bindings=self._binding_record(),
            retained_thread_pidfds=len(self.thread_fds),
            scope='incomplete V4 binding after a complete double frontier; reservation retained; '
                  'not worker terminal-event proof, zero RSS or release; original timed owned wait4 required')
        if self.binding_pending.terminal_event is not None:
            record.update(schema='llm-owned-postbinding-terminal-pending-v1',
                bound_worker_terminal_event=dict(self.binding_pending.terminal_event),
                scope='one original bound worker terminal event; incomplete postbinding frontier; '
                      'reservation retained; not group exit, zero RSS or release; original timed owned wait4 required')
        return record

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

    def _names(self, candidate, maximum_count=None):
        active, preceding = self.active_names, set(candidate)
        count = self._leader(base._status(base._read(self.group_fd, 'status')))
        names = base._task_names(self.tasks_fd)
        self.failure_context.update(reported_threads=count, observed_tasks=list(names))
        base._require(maximum_count is None or count <= maximum_count,
                      'exit-worker-frontier-change')
        base._require(str(self.visible) in names and set(names) <= set(active) and
            not set(names) & set(candidate), 'exit-worker-task-set')
        for name in active:
            if name not in names and name not in candidate:
                self._retire(name, candidate)
        newly_proved = [name for name in active if name in candidate and name not in preceding]
        if count != len(names) and count == len(active) and set(names) < set(active) and newly_proved:
            # This read crossed newly proved retirement, not a complete frontier.
            # The old count licenses one bounded recapture, never acceptance.
            self.failure_context['count_interruption'] = dict(prior_active_tasks=list(active),
                reported_threads=count, observed_tasks=list(names), newly_proved_retired_tasks=newly_proved,
                scope='discarded incomplete frontier; not success or resource evidence')
            raise _Recapture
        base._require(count == len(names), 'exit-worker-frontier-change')
        return names, count

    def _worker_frontier(self, candidate):
        names, count = self._names(candidate)
        shrinking = bool(candidate)
        result = {}
        for name in names:
            try:
                _, result[name] = self._fields(name, count, shrinking)
            except _CountDecreased as error:
                preceding = set(candidate)
                after, _ = self._names(candidate, maximum_count=error.reported_threads)
                newly_proved = [task for task in names if task in candidate and task not in preceding]
                base._require(set(after) < set(names) and newly_proved,
                              'exit-worker-frontier-change')
                self.failure_context['count_interruption'] = dict(prior_active_tasks=list(names),
                    reported_threads=error.reported_threads, observed_tasks=list(after),
                    newly_proved_retired_tasks=newly_proved,
                    scope='discarded incomplete frontier; not success or resource evidence')
                raise _Recapture from error
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
            if self.initial_capture.pending:
                self._initial_frontier()
                if self.binding_pending is not None and self.binding_pending.terminal_event is not None:
                    self._postbinding_roster(self.binding_pending.terminal_event['task'])
                return (self._binding_pending_record() if self.binding_pending is not None
                        else self._initial_record())
            if not self.baseline_qualified:
                self.acquisition_phase = 'initial-double-frontier'
                before, after = self._initial_frontier(), self._initial_frontier()
                if self.initial_capture.pending:
                    return self._initial_record()
                starts = {name: value['starttime'] for name, value in before.items()}
                base._require(starts == {name: value['starttime'] for name, value in after.items()} and
                    set(starts) == set(self.names), 'exit-task-starttime')
                self.starts = starts
                self.record = dict(profile=base.PROFILE, sample_started_ns=self.sample_started_ns,
                    classification_completed_ns=time.monotonic_ns(), tasks=list(self.names),
                    frontier_before=before, frontier_after=after,
                    scope='exit-only cleanup with no observable attached user-mm; not zero or physically released RSS')
                self.baseline_starts = dict(self.starts)
                self.active_names = self.names
                self.prebinding_record = dict(self.record)
                try:
                    self.acquisition_phase = 'worker-pidfd-bind'
                    self._bind_workers()
                    self.acquisition_phase = 'post-bind-double-frontier'
                    base.ExitOnlyObservation.recheck(self)
                    self.acquisition_phase = 'worker-pidfd-recheck'
                    self._check_bindings()
                except _BindingTaskMissing as error:
                    return self._retain_binding_task_loss(error)
                self._deadline()
                self.baseline_qualified = True
                self.acquisition_phase = 'qualified'
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
                    interruption = self.failure_context.pop('count_interruption', None)
                    if interruption is not None:
                        self.failure_context['interrupted_frontiers'][-1]['count_interruption'] = interruption
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
        if self.failed or not (self.baseline_qualified or
                self.initial_capture is not None and self.initial_capture.pending):
            return False
        try:
            self._owner()
            return super().belongs_to(pid, held_pidfd, owner_token)
        except (OSError, ValueError, KeyError, TypeError):
            return False

    def terminal_belongs_to(self, pid, held_pidfd, owner_token):
        """Held capability only; never authorizes a live poll or a recheck.

        The supervisor calls this only after its exact owned wait4 receipt.
        Reaped pidfd fdinfo says -1, so live namespace/proc checks cannot apply.
        No caller-supplied terminal boolean or later identity can mint authority.
        """
        if self.failed or not (self.baseline_qualified or
                self.initial_capture is not None and self.initial_capture.pending):
            return False
        try:
            self._held_capabilities()
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
