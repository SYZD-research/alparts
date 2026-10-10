"""M5v: who sees which rows of a workspace's audit view (2026-10-09).

Written from services/audit-log.service.ts (b074bad): a row is in the view
of workspace W for viewer v when

  in scope    target is workspace W, or details.workspaceId = W (as text)
  not personal  action is not channel.preference.* / message.bookmark.*
  and (not channel activity, or v is the actor, or the row's channel is one
      v can see now)            channel = details.channelId, else the target
                                when it is a channel (compared as text)

Channel activity is matched by LIKE patterns. This model keeps its own
catalog of every audit action the server writes, with the class the threat
model gives it ("activity inside a channel ... only to viewers who can
currently see that channel ... workspace management events stay visible to
every audit viewer"), and checks:

  AV-catalog  the catalog covers every action literal in the server source
              (a new action makes this a MODEL-GAP until it is classified)
  AV-class    the implementation's patterns put each action in its class
  AV-case     ids in other letter cases cannot reach the services, which
              would store them as given and so leave the text-compared scope
              (the real canonical-id checks, on generated paths)

  AV-links    the view returns no chain hashes, which would show that rows the
              viewer may not see were written in between (the fields the
              implementation's formatter returns)

and records one property of the design as a LIMIT.
"""
from __future__ import annotations

import random
import re
from pathlib import Path

from common import record
from harness import HarnessError, run_harness

REPO = Path(__file__).resolve().parent.parent
SOURCES = [REPO / 'packages/server/src' / d for d in ('services', 'middleware', 'routes', 'scripts')]
AUDIT_LOG_SERVICE = REPO / 'packages/server/src/services/audit-log.service.ts'

# action -> class: activity | management | personal | account (no workspace scope)
ACTIVITY = 'activity'
MANAGEMENT = 'management'
PERSONAL = 'personal'
ACCOUNT = 'account'
CATALOG: dict[str, str] = {}
for name in ('message.create', 'message.create.replay', 'message.edit', 'message.edit.replay', 'message.delete',
             'message.delete.replay', 'message.reaction.add', 'message.reaction.remove', 'message.pin.add',
             'message.pin.remove', 'message.pin.broadcast_failed',
             'forum.post.create', 'forum.post.create.replay', 'forum.post.lock', 'forum.post.unlock',
             'forum.post.resolve', 'forum.post.unresolve', 'forum.post.tags',
             'dm.create', 'dm.reuse', 'channel.member.add', 'channel.member.remove',
             'channel.key.acknowledge', 'channel.key.acknowledge.replay', 'channel.key.delivery.add',
             'channel.key.epoch.abort', 'channel.key.epoch.abort.replay', 'channel.key.epoch.fresh_start',
             'channel.key.epoch.propose', 'channel.key.epoch.recovery.propose', 'channel.key.group.create',
             'channel.key.group.commit', 'channel.key.group.fresh_start', 'channel.key.group.replay',
             # A device publishes a package for every channel it can see: who is in a private channel or DM.
             'channel.mls.member_package', 'channel.mls.member_package.replay', 'channel.mls.key_package',
             'attachment.upload.create', 'attachment.upload.replay', 'attachment.upload.cancel',
             'attachment.upload.cancel.replay', 'attachment.create'):
    CATALOG[name] = ACTIVITY
for name in ('channel.create', 'channel.update', 'channel.delete', 'category.create', 'category.update',
             'category.delete', 'channel.permission-override.upsert', 'channel.permission-override.delete',
             'category.permission-override.upsert', 'category.permission-override.delete',
             'forum.tag.create', 'forum.tag.update', 'forum.tag.delete',
             'role.create', 'role.update', 'role.delete', 'role.assign', 'role.unassign',
             'workspace.create', 'workspace.member.remove', 'workspace.invitation.create',
             'workspace.invitation.revoke', 'workspace.invitation.use',
             'profile.flag', 'profile.unflag', 'profile.appeal.request', 'profile.appeal.deny', 'profile.announce',
             'audit.view', 'audit.integrity.view'):
    CATALOG[name] = MANAGEMENT
for name in ('channel.preference.update', 'message.bookmark.add', 'message.bookmark.remove'):
    CATALOG[name] = PERSONAL
for name in ('account.disable', 'account.enable', 'account.password.reset', 'audit.checkpoint.provision',
             'audit.checkpoint_write_failed_after_commit', 'authentication.challenge',
             'authentication.challenge.consume', 'authentication.step_up', 'authentication.step_up.consume',
             'device.approve', 'device.bind', 'device.register', 'device.revoke', 'device.revoke.replay',
             'passkey.delete', 'passkey.register', 'recovery.access.enroll', 'recovery.configure', 'recovery.device',
             'recovery.disable', 'recovery.key.backup', 'security.audit.truncation-control', 'session.revoke',
             'session.revoke_all', 'user.avatar.remove', 'user.avatar.update', 'user.login', 'user.login.failed',
             'user.logout', 'user.password.change', 'user.password_login.disable', 'user.password_login.enable',
             'user.profile.update', 'user.register'):
    CATALOG[name] = ACCOUNT
# Names assembled from parts at run time (the parts are listed above).
TEMPLATES = {'message.reaction.': ('add', 'remove'), 'role.': ('assign', 'unassign'),
             'channel.key.group.': ('create', 'commit', 'fresh_start')}
PREFIXES = '|'.join(['account', 'attachment', 'audit', 'authentication', 'category', 'channel', 'device', 'dm',
                     'forum', 'message', 'passkey', 'profile', 'recovery', 'role', 'security', 'session', 'user',
                     'workspace'])


def source_actions() -> set[str]:
    found = set()
    pattern = re.compile(rf"'((?:{PREFIXES})\.[a-z0-9_.-]+)'")
    for root in SOURCES:
        for path in root.rglob('*.ts'):
            if '.test.' in path.name:
                continue
            found |= set(pattern.findall(path.read_text()))
    return found


def implementation_patterns() -> tuple[list[str], list[str]]:
    text = AUDIT_LOG_SERVICE.read_text()

    def patterns(name: str) -> list[str]:
        match = re.search(rf'const {name} = \[(.*?)\];', text, re.S)
        if not match:
            raise HarnessError(f'{name} not found in audit-log.service.ts')
        return re.findall(r"'([^']+)'", match.group(1))
    return patterns('CHANNEL_ACTIVITY_ACTIONS'), patterns('PERSONAL_ACTIONS')


CHAIN_FIELDS = ('prevHash', 'hash')
# formatAuditLog at ce09b19, before the 2026-10-09 fix (the control's input).
FORMATTER_BEFORE_FIX = """
function formatAuditLog(row: typeof auditLogs.$inferSelect) {
  return {
    id: row.id,
    actorId: row.actorId,
    action: row.action,
    targetType: row.targetType,
    targetId: row.targetId,
    details: row.details,
    prevHash: row.prevHash,
    hash: row.hash,
    createdAt: row.createdAt.toISOString(),
  };
}
"""


def view_fields(text: str | None = None) -> list[str]:
    """The fields formatAuditLog returns for each row of the view."""
    text = AUDIT_LOG_SERVICE.read_text() if text is None else text
    match = re.search(r'function formatAuditLog\([^)]*\) \{\s*return \{(.*?)\};\s*\}', text, re.S)
    if not match:
        raise HarnessError('formatAuditLog not found in audit-log.service.ts')
    return re.findall(r'^\s*(\w+):', match.group(1), re.M)


def like(value: str, pattern: str) -> bool:
    return re.fullmatch(re.escape(pattern).replace('%', '.*').replace('_', '.'), value) is not None


def implementation_class(action: str, activity: list[str], personal: list[str]) -> str:
    if any(like(action, p) for p in personal):
        return PERSONAL
    if any(like(action, p) for p in activity):
        return ACTIVITY
    return MANAGEMENT


def run() -> None:
    print('== M5v: the workspace audit view (who sees which rows) ==')
    try:
        literals = source_actions()
        activity, personal = implementation_patterns()
    except (OSError, HarnessError) as error:
        record('M5v', 'AV-catalog', 'the catalog covers every audit action the server writes', 'HOLDS', False,
               str(error), incomplete=True)
        return
    unknown = sorted(name for name in literals
                     if name not in CATALOG and not any(name == t for t in TEMPLATES) and not name.endswith('.'))
    print(f'  M5v: {len(literals)} action names in the server source, {len(CATALOG)} in the catalog')
    record('M5v', 'AV-catalog', 'the catalog covers every audit action name in the server source', 'HOLDS', False,
           f'unclassified: {", ".join(unknown)}' if unknown else '', incomplete=bool(unknown))

    wrong = []
    for action, expected in sorted(CATALOG.items()):
        if expected == ACCOUNT:
            continue                 # no workspace scope: never in a workspace view
        actual = implementation_class(action, activity, personal)
        if actual != expected:
            wrong.append(f'{action}: expected {expected}, implementation treats it as {actual}')
    record('M5v', 'AV-class', 'every action is shown as its class requires (channel activity only to viewers of '
                              'the channel and the actor; personal settings to nobody)', 'HOLDS', bool(wrong),
           witness=wrong)

    # AV-case: generated paths with ids in random letter cases.
    rng = random.Random(20261009)
    paths, expected_paths = [], []
    for _ in range(400):
        ids = [''.join(rng.choice('0123456789abcdef') for _ in range(32)) for _ in range(rng.randint(1, 3))]
        segments = []
        bad = False
        for raw in ids:
            uuid = f'{raw[:8]}-{raw[8:12]}-4{raw[13:16]}-8{raw[17:20]}-{raw[20:]}'
            if rng.random() < 0.5:
                mixed = ''.join(c.upper() if c.isalpha() and rng.random() < 0.5 else c for c in uuid)
                bad = bad or mixed != uuid
                uuid = mixed
            if rng.random() < 0.2:
                uuid = ''.join(f'%{ord(c):02X}' if rng.random() < 0.3 else c for c in uuid)
            segments += [rng.choice(['workspaces', 'channels', 'messages', 'forum', 'members']), uuid]
        paths.append('/' + '/'.join(segments))
        expected_paths.append(bad)
    ids = ['00000000-0000-4000-8000-00000000000a', '00000000-0000-4000-8000-00000000000A', 'not-a-uuid']
    try:
        out = run_harness('canonical-id-harness.mts', {'paths': paths, 'ids': ids})
        if not isinstance(out, dict) or len(out.get('paths', [])) != len(paths) or len(out.get('ids', [])) != len(ids):
            raise HarnessError('incomplete canonical-id output')
    except HarnessError as error:
        record('M5v', 'AV-case', 'ids in another letter case never reach the services', 'HOLDS', False, str(error),
               incomplete=True)
    else:
        mismatched = [f'{p}: expected {"reject" if e else "accept"}' for p, e, r in zip(paths, expected_paths, out['paths'])
                      if e != r]
        if out['ids'] != [True, False, False]:
            mismatched.append(f'channel id schema: {out["ids"]}')
        record('M5v', 'AV-case', 'a request path or socket channel id that names an id in another letter case is '
                                 'refused (400 generated paths, percent-encoded too)', 'HOLDS', bool(mismatched),
               witness=mismatched[:12])

    try:
        fields = view_fields()
    except HarnessError as error:
        record('M5v', 'AV-links', 'the view returns no chain hashes', 'HOLDS', False, str(error), incomplete=True)
    else:
        leaked = [f for f in fields if f in CHAIN_FIELDS]
        record('M5v', 'AV-links', 'a viewer cannot tell from the view that rows it may not see were written between '
                                  'two rows it sees (no chain hashes in the view)', 'HOLDS', bool(leaked),
               f'formatAuditLog returns {", ".join(leaked)}: b.prevHash != a.hash means rows were appended in between'
               if leaked else '')
        before = [f for f in view_fields(FORMATTER_BEFORE_FIX) if f in CHAIN_FIELDS]
        record('M5v', 'AV-links-ctl', 'before the fix: the view returned prevHash and hash', 'CONTROL', bool(before),
               witness=[f'formatAuditLog returned {", ".join(before)}'] if before else [])
    record('M5v', 'AV-L-now', 'channel activity follows the viewer\'s current access, so gaining access to a '
                              'channel shows its earlier rows and losing it hides them', 'LIMIT', True,
           'visibleChannelIds() evaluates the current authorization snapshot for every historical row')


if __name__ == '__main__':
    run()
