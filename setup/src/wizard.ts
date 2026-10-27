import { readFileSync } from 'node:fs';
import { isIPv4 } from 'node:net';
import { SetupError, type Context } from './context.ts';
import { localAddresses, reachesThisHost, resolveDomain } from './network.ts';
import { voicePortRange } from './render.ts';
import { isAgeRecipient, isEmailAddress, isHostName, isPort, isPrivateIPv4, normalizeDomain, normalizeTime, type BackupSettings, type EmailSettings, type Settings } from './settings.ts';
import { checkSmtp } from './smtp.ts';

/** What each reason a mail server check fails means to the operator. */
export const SMTP_FAILURES = {
  connect: 'email.failConnect',
  tls: 'email.failTls',
  starttls: 'email.failStarttls',
  auth: 'email.failAuth',
  protocol: 'email.failProtocol',
} as const;

/** What the operator decides; everything else is generated. Also the shape of an --answers file. */
export interface Answers {
  domain: string;
  acmeEmail: string | null;
  certificates: 'public' | 'local';
  email: EmailSettings;
  /** Only when the mail server needs a sign-in. */
  smtpPassword: string | null;
  voice: { relay: boolean; publicAddress: string | null };
  backup: Pick<BackupSettings, 'recipient' | 'time'> | null;
}

export const DEFAULT_BACKUP_TIME = '04:00';

function invalid(field: string): never {
  throw new SetupError('error.answer', { field });
}

/**
 * Reads an answers file for unattended installs. The same rules apply as to
 * typed answers; the SMTP password may come from a separate file.
 */
export function parseAnswersFile(path: string): Answers {
  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>;
  } catch (error) {
    throw new SetupError('error.answersFile', { detail: (error as Error).message });
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) invalid('(root)');

  const domain = normalizeDomain(String(raw.domain ?? '')) ?? invalid('domain');
  const acmeEmail = raw.acmeEmail === undefined || raw.acmeEmail === null ? null : String(raw.acmeEmail);
  if (acmeEmail !== null && !isEmailAddress(acmeEmail)) invalid('acmeEmail');
  const certificates = raw.certificates === undefined ? 'public' : raw.certificates;
  if (certificates !== 'public' && certificates !== 'local') invalid('certificates');

  const emailRaw = (raw.email ?? {}) as Record<string, unknown>;
  let email: EmailSettings;
  let smtpPassword: string | null = null;
  if (emailRaw.mode === 'disabled') {
    email = { mode: 'disabled' };
  } else if (emailRaw.mode === 'smtp') {
    const host = String(emailRaw.host ?? '').trim().toLowerCase();
    if (!isHostName(host)) invalid('email.host');
    const security = emailRaw.security ?? 'starttls';
    if (security !== 'starttls' && security !== 'tls') invalid('email.security');
    const port = emailRaw.port === undefined ? (security === 'tls' ? 465 : 587) : Number(emailRaw.port);
    if (!isPort(port)) invalid('email.port');
    const from = String(emailRaw.from ?? '');
    if (!isEmailAddress(from)) invalid('email.from');
    const user = emailRaw.user === undefined || emailRaw.user === null || emailRaw.user === '' ? null : String(emailRaw.user);
    if (user !== null && /[\r\n]/.test(user)) invalid('email.user');
    if (user !== null) {
      if (typeof emailRaw.passwordFile === 'string') {
        try {
          smtpPassword = readFileSync(emailRaw.passwordFile, 'utf8').replace(/\r?\n$/, '');
        } catch {
          invalid('email.passwordFile');
        }
      } else if (typeof emailRaw.password === 'string') {
        smtpPassword = emailRaw.password;
      }
      if (!smtpPassword) invalid('email.password');
    }
    email = { mode: 'smtp', host, port, security, from, user };
  } else {
    invalid('email.mode');
  }

  const voiceRaw = (raw.voice ?? { relay: true }) as Record<string, unknown>;
  if (typeof voiceRaw.relay !== 'boolean') invalid('voice.relay');
  const publicAddress = voiceRaw.publicAddress === undefined || voiceRaw.publicAddress === null ? null : String(voiceRaw.publicAddress);
  if (publicAddress !== null && !isIPv4(publicAddress)) invalid('voice.publicAddress');

  let backup: Answers['backup'] = null;
  if (raw.backup !== undefined && raw.backup !== null) {
    const backupRaw = raw.backup as Record<string, unknown>;
    const recipient = String(backupRaw.recipient ?? '');
    if (!isAgeRecipient(recipient)) invalid('backup.recipient');
    const time = normalizeTime(String(backupRaw.time ?? DEFAULT_BACKUP_TIME)) ?? invalid('backup.time');
    backup = { recipient, time };
  }
  return { domain, acmeEmail, certificates, email, smtpPassword, voice: { relay: voiceRaw.relay, publicAddress }, backup };
}

/** Explains what the domain points to, and returns its first IPv4 address for the voice relay. */
async function checkDomain(context: Context, domain: string, certificates: Answers['certificates']): Promise<{ address: string | null; accepted: boolean }> {
  const { t, ui } = context;
  const resolved = await resolveDomain(domain);
  if (resolved.v4.length === 0 && resolved.v6.length === 0) {
    if (certificates === 'local') return { address: null, accepted: true };
    ui.warning(t('domain.notResolved', { domain }));
    return { address: null, accepted: false };
  }
  ui.success(t('domain.resolves', { domain, addresses: [...resolved.v4, ...resolved.v6].join(', ') }));
  let accepted = true;
  if (resolved.v6.length > 0 && localAddresses().v6.length === 0 && certificates === 'public') {
    ui.warning(t('domain.ipv6Mismatch', { domain }));
    accepted = false;
  }
  if (certificates === 'public') {
    const running = (await context.docker.services()).some((service) => service.service === 'proxy' && service.state === 'running');
    if (!running) {
      if (await reachesThisHost(domain)) ui.success(t('domain.reachable'));
      else {
        ui.warning(t('domain.notReachable', { domain }));
        accepted = false;
      }
    }
  }
  return { address: resolved.v4[0] ?? null, accepted };
}

async function askEmail(context: Context, previous: Answers | null, savedPassword: string | null): Promise<{ email: EmailSettings; smtpPassword: string | null; keepPassword: boolean }> {
  const { t, ui } = context;
  ui.section(t('section.email'));
  ui.note(t('email.explain'));
  const before = previous?.email.mode === 'smtp' ? previous.email : null;
  for (;;) {
    if (!(await ui.confirm(t('email.useSmtp'), previous?.email.mode !== 'disabled', t('prompt.invalidYesNo')))) {
      ui.warning(t('email.disableWarning'));
      if (await ui.confirm(t('email.disableConfirm'), false, t('prompt.invalidYesNo'))) {
        return { email: { mode: 'disabled' }, smtpPassword: null, keepPassword: false };
      }
      continue;
    }
    const host = (await ui.ask(t('email.host'), {
      default: before?.host,
      validate: (answer) => (isHostName(answer.toLowerCase()) ? null : t('email.hostInvalid')),
    })).toLowerCase();
    const security = await ui.choose(t('email.security'), [
      { value: 'starttls' as const, label: t('email.securityStarttls') },
      { value: 'tls' as const, label: t('email.securityTls') },
    ], before?.security === 'tls' ? 1 : 0, t('prompt.invalidChoice'));
    const defaultPort = before && before.security === security ? before.port : security === 'tls' ? 465 : 587;
    const port = Number(await ui.ask(t('email.port'), {
      default: String(defaultPort),
      validate: (answer) => (/^\d+$/.test(answer) && isPort(Number(answer)) ? null : t('email.portInvalid')),
    }));
    const from = await ui.ask(t('email.from'), {
      default: before?.from,
      validate: (answer) => (isEmailAddress(answer) ? null : t('email.fromInvalid')),
    });
    const userAnswer = await ui.ask(t('email.user'), { default: before?.user ?? undefined });
    const user = userAnswer || null;
    let smtpPassword: string | null = null;
    let keepPassword = false;
    if (user !== null) {
      // An unchanged sign-in keeps the saved password when the answer is left empty.
      const canKeep = before?.user === user && Boolean(savedPassword);
      const password = await ui.ask(t('email.password'), {
        secret: true,
        validate: (answer) => (answer || canKeep ? null : t('email.passwordEmpty')),
      });
      if (password) smtpPassword = password;
      else keepPassword = true;
    }
    const email: EmailSettings = { mode: 'smtp', host, port, security, from, user };
    const password = keepPassword ? savedPassword : smtpPassword;
    const result = await ui.task(t('email.checking'), () => checkSmtp({ host, port, security, user, password }),
      (check) => (check.ok ? t(user ? 'email.signedIn' : 'email.connected') : { warning: t(SMTP_FAILURES[check.reason]) }));
    if (result.ok) return { email, smtpPassword, keepPassword };
    if (await ui.confirm(t('email.retry'), true, t('prompt.invalidYesNo'))) continue;
    if (await ui.confirm(t('email.useAnyway'), false, t('prompt.invalidYesNo'))) return { email, smtpPassword, keepPassword };
  }
}

/** The backup questions: whether, the public key, and the time. */
export async function askBackup(context: Context, previous: Answers['backup'], enableByDefault: boolean): Promise<Answers['backup']> {
  const { t, ui } = context;
  ui.section(t('section.backup'));
  ui.note(t('backup.explain'));
  if (!(await ui.confirm(t('backup.enable'), enableByDefault, t('prompt.invalidYesNo')))) {
    ui.note(t('backup.later', { command: context.command }));
    return null;
  }
  const recipient = await ui.ask(t('backup.recipient'), {
    default: previous?.recipient,
    validate: (answer) => (isAgeRecipient(answer) ? null : t('backup.recipientInvalid')),
  });
  const time = normalizeTime(await ui.ask(t('backup.time'), {
    default: previous?.time ?? DEFAULT_BACKUP_TIME,
    validate: (answer) => (normalizeTime(answer) ? null : t('backup.timeInvalid')),
  }))!;
  return { recipient, time };
}

export interface WizardResult {
  answers: Answers;
  /** The saved SMTP password stays as it is. */
  keepSmtpPassword: boolean;
}

/**
 * The questions, with earlier answers (a resumed or reconfigured install) as
 * the defaults. `savedPassword` is the SMTP password already stored, which an
 * empty answer keeps.
 */
export async function askQuestions(context: Context, previous: Answers | null, savedPassword: string | null = null): Promise<WizardResult> {
  const { t, ui } = context;
  const certificates = previous?.certificates ?? 'public';

  ui.section(t('section.domain'));
  ui.note(t('domain.explain'));
  let domain = '';
  let domainAddress: string | null = null;
  for (;;) {
    domain = normalizeDomain(await ui.ask(t('domain.prompt'), {
      default: previous?.domain,
      validate: (answer) => (normalizeDomain(answer) ? null : t('domain.invalid')),
    }))!;
    const check = await checkDomain(context, domain, certificates);
    domainAddress = check.address;
    if (check.accepted || await ui.confirm(t('domain.continueAnyway'), false, t('prompt.invalidYesNo'))) break;
  }

  const { email, smtpPassword, keepPassword } = await askEmail(context, previous, savedPassword);

  ui.section(t('section.voice'));
  ui.note(t('voice.explain'));
  const relay = await ui.confirm(t('voice.relay'), previous?.voice.relay ?? true, t('prompt.invalidYesNo'));
  let publicAddress: string | null = null;
  if (relay) {
    publicAddress = await ui.ask(t('voice.address'), {
      default: previous?.voice.publicAddress ?? domainAddress ?? undefined,
      validate: (answer) => (isIPv4(answer) ? null : t('voice.addressInvalid')),
    });
    if (isPrivateIPv4(publicAddress)) ui.warning(t('voice.privateAddress', { address: publicAddress }));
  } else {
    ui.note(t('voice.directOnly'));
  }

  const backup = await askBackup(context, previous ? previous.backup : null, previous ? previous.backup !== null : true);

  return {
    answers: { domain, acmeEmail: previous?.acmeEmail ?? null, certificates, email, smtpPassword, voice: { relay, publicAddress }, backup },
    keepSmtpPassword: keepPassword,
  };
}

/** The settings a wizard or an answers file leads to, for the review before installing. */
export function reviewLines(context: Context, settings: Settings): Array<[string, string]> {
  const { t } = context;
  const email = settings.email;
  return [
    [t('confirm.domain'), `https://${settings.domain}`],
    [t('confirm.email'), email.mode === 'smtp' ? t('confirm.emailSmtp', { from: email.from, host: email.host, port: email.port }) : t('confirm.emailDisabled')],
    [t('confirm.voice'), settings.voice.relay
      ? t('confirm.voiceRelay', { address: settings.voice.publicAddress ?? '', ports: voicePortRange(settings) })
      : t('confirm.voiceDirect')],
    [t('confirm.backup'), settings.backup ? t('confirm.backupDaily', { time: settings.backup.time }) : t('confirm.backupNone')],
  ];
}

/** Answers the current settings stand for, as defaults for the questions. */
export function answersFromSettings(settings: Settings): Answers {
  return {
    domain: settings.domain,
    acmeEmail: settings.acmeEmail,
    certificates: settings.certificates,
    email: settings.email,
    smtpPassword: null,
    voice: { relay: settings.voice.relay, publicAddress: settings.voice.publicAddress },
    backup: settings.backup ? { recipient: settings.backup.recipient, time: settings.backup.time } : null,
  };
}
