export async function focusMessageElement(
  messageId: string,
  options: { attempts?: number; behavior?: ScrollBehavior } = {},
): Promise<boolean> {
  const attempts = options.attempts ?? 30;
  const behavior = options.behavior ?? 'smooth';
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const target = document.getElementById(`message-${messageId}`);
    if (target instanceof HTMLElement) {
      target.scrollIntoView({ block: 'center', behavior });
      target.focus({ preventScroll: true });
      target.dataset.permalinkHighlight = 'true';
      window.setTimeout(() => {
        if (target.dataset.permalinkHighlight === 'true') delete target.dataset.permalinkHighlight;
      }, 4_000);
      return true;
    }
    await new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));
  }
  return false;
}
