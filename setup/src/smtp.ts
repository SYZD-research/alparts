import { isIP, connect as tcpConnect, type Socket } from 'node:net';
import { connect as tlsConnect, type ConnectionOptions, type TLSSocket } from 'node:tls';

export type SmtpCheck =
  | { ok: true }
  | { ok: false; reason: 'connect' | 'tls' | 'starttls' | 'auth' | 'protocol'; detail: string };

export interface SmtpOptions {
  host: string;
  port: number;
  /** `tls` from the first byte (usually 465), or `starttls` (usually 587), which the server requires in production. */
  security: 'tls' | 'starttls';
  user: string | null;
  password: string | null;
  timeoutMs?: number;
  /** For tests: the authority that signed the server's certificate. */
  ca?: string;
}

/** Reads SMTP replies, joining multi-line ones (`250-…` lines up to `250 …`). */
class ReplyReader {
  private buffer = '';
  private lines: string[] = [];
  private waiting: ((reply: { code: number; text: string }) => void) | null = null;
  private failure: ((error: Error) => void) | null = null;

  attach(socket: Socket | TLSSocket): void {
    socket.setEncoding('utf8');
    socket.on('data', (chunk: string) => {
      this.buffer += chunk;
      let index: number;
      while ((index = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, index).replace(/\r$/, '');
        this.buffer = this.buffer.slice(index + 1);
        this.lines.push(line);
        if (/^\d{3} /.test(line) || /^\d{3}$/.test(line)) this.deliver();
      }
      if (this.buffer.length > 64 * 1024) this.failure?.(new Error('Reply too long'));
    });
    socket.on('error', (error) => this.failure?.(error));
    socket.on('close', () => this.failure?.(new Error('Connection closed')));
  }

  detach(socket: Socket | TLSSocket): void {
    socket.removeAllListeners('data');
    socket.removeAllListeners('error');
    socket.removeAllListeners('close');
  }

  private deliver(): void {
    const lines = this.lines;
    this.lines = [];
    const code = Number(lines.at(-1)!.slice(0, 3));
    this.waiting?.({ code, text: lines.map((line) => line.slice(4)).join('\n') });
    this.waiting = null;
    this.failure = null;
  }

  next(): Promise<{ code: number; text: string }> {
    return new Promise((resolve, reject) => {
      this.waiting = resolve;
      this.failure = reject;
    });
  }
}

class Step extends Error {
  readonly reason: Exclude<SmtpCheck, { ok: true }>['reason'];

  constructor(reason: Exclude<SmtpCheck, { ok: true }>['reason'], detail: string) {
    super(detail);
    this.reason = reason;
  }
}

/**
 * Connects to the mail server the way the app will, with a verified
 * certificate, and signs in when a user is set. Nothing is sent.
 */
export async function checkSmtp(options: SmtpOptions): Promise<SmtpCheck> {
  const timeoutMs = options.timeoutMs ?? 15_000;
  let socket: Socket | TLSSocket | null = null;
  const timer = setTimeout(() => socket?.destroy(new Error('Timed out')), timeoutMs);
  // A server name for SNI must be a host name; an address is checked against the certificate as it is.
  const tlsOptions: ConnectionOptions = {
    host: options.host,
    port: options.port,
    ...(isIP(options.host) ? {} : { servername: options.host }),
    ...(options.ca ? { ca: options.ca } : {}),
  };
  try {
    const reader = new ReplyReader();
    const command = async (line: string, expect: number[], reason: Step['reason']) => {
      socket!.write(`${line}\r\n`);
      const reply = await reader.next();
      if (!expect.includes(reply.code)) throw new Step(reason, `${line.split(' ')[0]}: ${reply.code} ${reply.text}`);
      return reply;
    };

    if (options.security === 'tls') {
      socket = await new Promise<TLSSocket>((resolve, reject) => {
        const tls = tlsConnect(tlsOptions, () => resolve(tls));
        tls.once('error', (error) => reject(new Step(isCertificateError(error) ? 'tls' : 'connect', error.message)));
      });
      reader.attach(socket);
    } else {
      socket = await new Promise<Socket>((resolve, reject) => {
        const tcp = tcpConnect({ host: options.host, port: options.port }, () => resolve(tcp));
        tcp.once('error', (error) => reject(new Step('connect', error.message)));
      });
      reader.attach(socket);
    }

    const greeting = await reader.next().catch((error: Error) => { throw new Step('connect', error.message); });
    if (greeting.code !== 220) throw new Step('protocol', `greeting ${greeting.code}`);
    let hello = await command('EHLO alparts-setup', [250], 'protocol');

    if (options.security === 'starttls') {
      if (!/^STARTTLS$/im.test(hello.text)) throw new Step('starttls', 'STARTTLS not offered');
      await command('STARTTLS', [220], 'starttls');
      const plain = socket as Socket;
      reader.detach(plain);
      socket = await new Promise<TLSSocket>((resolve, reject) => {
        const tls = tlsConnect({ ...tlsOptions, socket: plain }, () => resolve(tls));
        tls.once('error', (error) => reject(new Step('tls', error.message)));
      });
      reader.attach(socket);
      hello = await command('EHLO alparts-setup', [250], 'protocol');
    }

    if (options.user !== null) {
      const mechanisms = /^AUTH[ =](.*)$/im.exec(hello.text)?.[1]?.toUpperCase().split(/\s+/) ?? [];
      const user = options.user;
      const password = options.password ?? '';
      if (mechanisms.includes('PLAIN')) {
        await command(`AUTH PLAIN ${Buffer.from(`\u0000${user}\u0000${password}`).toString('base64')}`, [235], 'auth');
      } else if (mechanisms.includes('LOGIN')) {
        await command('AUTH LOGIN', [334], 'auth');
        await command(Buffer.from(user).toString('base64'), [334], 'auth');
        await command(Buffer.from(password).toString('base64'), [235], 'auth');
      } else {
        throw new Step('auth', 'No supported sign-in method');
      }
    }
    socket.write('QUIT\r\n');
    return { ok: true };
  } catch (error) {
    if (error instanceof Step) return { ok: false, reason: error.reason, detail: error.message };
    return { ok: false, reason: 'connect', detail: (error as Error).message };
  } finally {
    clearTimeout(timer);
    socket?.destroy();
  }
}

function isCertificateError(error: Error): boolean {
  const code = (error as NodeJS.ErrnoException).code ?? '';
  return /CERT|SELF_SIGNED|UNABLE_TO|ALTNAME|HOSTNAME/i.test(code);
}
