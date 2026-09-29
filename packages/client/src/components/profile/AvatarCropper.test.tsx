import { renderToStaticMarkup } from 'react-dom/server';
import { describe, expect, it } from 'vitest';
import { AvatarCropper } from './AvatarCropper';

describe('avatar cropper', () => {
  it('offers moving, zooming and resizing before the picture is saved', () => {
    const bitmap = { width: 800, height: 400, close: () => undefined } as ImageBitmap;
    const html = renderToStaticMarkup(
      <AvatarCropper bitmap={bitmap} busy={false} onConfirm={() => undefined} onCancel={() => undefined} />,
    );
    expect(html).toContain('aria-label="縮小"');
    expect(html).toContain('aria-label="拡大"');
    expect(html).toContain('枠の大きさ');
    expect(html.match(/data-corner=/g)).toHaveLength(4);
    expect(html).toContain('この範囲で設定');
    // The whole-picture start: a 144px frame centred in the 288px editor.
    expect(html).toContain('left:72px;top:72px;width:144px;height:144px');
  });
});
