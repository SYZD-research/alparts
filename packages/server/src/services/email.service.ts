import nodemailer, { type Transporter } from 'nodemailer';
import { config } from '../config/index.js';
import { logInfo } from '../security/logger.js';

export interface OutgoingEmail {
  to: string;
  subject: string;
  text: string;
}

/**
 * How mail reaches people in this deployment. Without SMTP, development and
 * tests keep messages in memory instead; production has no way to send.
 */
export type EmailDelivery = 'smtp' | 'development' | 'unavailable';

export function emailDelivery(): EmailDelivery {
  if (config.email.smtp) return 'smtp';
  return config.isProduction ? 'unavailable' : 'development';
}

const MAX_DEVELOPMENT_EMAILS = 50;
const developmentOutbox: OutgoingEmail[] = [];

/** Messages "sent" without SMTP outside production, newest last. */
export function developmentEmails(): readonly OutgoingEmail[] {
  return developmentOutbox;
}

let transporter: Transporter | null = null;

function smtpTransport(): Transporter {
  const smtp = config.email.smtp;
  if (!smtp) throw new Error('EMAIL_UNAVAILABLE');
  transporter ??= nodemailer.createTransport({
    host: smtp.host,
    port: smtp.port,
    secure: smtp.secure,
    requireTLS: !smtp.secure && config.isProduction,
    auth: smtp.user ? { user: smtp.user, pass: smtp.password ?? '' } : undefined,
    connectionTimeout: smtp.timeoutMs,
    greetingTimeout: smtp.timeoutMs,
    socketTimeout: smtp.timeoutMs,
    tls: { rejectUnauthorized: true, minVersion: 'TLSv1.2' },
    disableFileAccess: true,
    disableUrlAccess: true,
  });
  return transporter;
}

export async function sendEmail(message: OutgoingEmail): Promise<void> {
  const delivery = emailDelivery();
  if (delivery === 'smtp') {
    await smtpTransport().sendMail({
      from: config.email.smtp!.from,
      to: message.to,
      subject: message.subject,
      text: message.text,
    });
    return;
  }
  if (delivery === 'development') {
    developmentOutbox.push(message);
    if (developmentOutbox.length > MAX_DEVELOPMENT_EMAILS) developmentOutbox.shift();
    if (config.nodeEnv === 'development') {
      logInfo('email.development_delivery', { to: message.to, subject: message.subject, text: message.text });
    }
    return;
  }
  throw new Error('EMAIL_UNAVAILABLE');
}
