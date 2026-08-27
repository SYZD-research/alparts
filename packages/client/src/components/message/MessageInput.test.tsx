import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { MessageInput } from './MessageInput';

describe('MessageInput', () => {
  it('renders an explicit submit control for pointer and touch users', () => {
    const html = renderToStaticMarkup(
      <MessageInput channelId="00000000-0000-4000-8000-000000000001" />,
    );

    expect(html).toContain('type="submit"');
    expect(html).toContain('>送信</button>');
    expect(html).toContain('画像・ファイル');
  });
});
