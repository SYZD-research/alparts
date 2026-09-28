/** Shared by account lookup, invitation binding, and admission budgets. */
export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase().normalize('NFC');
}
