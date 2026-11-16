"""Render docs/demo.gif from a real captured session: `$ ` lines are typed, output scrolls in.

docs/demo.txt holds each command as `$ command` followed by its captured output.
    python docs/make_demo_gif.py docs/demo.txt docs/demo.gif
"""
import re, sys, textwrap
from PIL import Image, ImageDraw, ImageFont

COLS, ROWS, LH, PAD, BAR = 92, 24, 18, 16, 30
BG, FG, DIM = (13, 17, 23), (201, 209, 217), (110, 118, 129)
RED, GREEN, AMBER, BLUE = (248, 81, 73), (63, 185, 80), (210, 153, 34), (88, 166, 255)
RULES = [(r'\bFAIL\b|\bBROKEN\b|\bHIGH\b', RED), (r'\bPASS\b', GREEN), (r'\bMEDIUM\b|\bLOW\b', AMBER)]


def font():
    for f in ('consola.ttf', 'DejaVuSansMono.ttf', 'Menlo.ttc'):
        try:
            return ImageFont.truetype(f, 15)
        except OSError:
            pass
    return ImageFont.load_default()


def draw(lines, cursor, f):
    CW = f.getlength('M')  # monospace advance, so colour spans land on the same grid
    w, h = int(COLS * CW) + 2 * PAD, ROWS * LH + 2 * PAD + BAR
    im = Image.new('RGB', (w, h), BG)
    d = ImageDraw.Draw(im)
    d.rectangle((0, 0, w, BAR), fill=(22, 27, 34))
    for i, c in enumerate(((255, 95, 86), (255, 189, 46), (39, 201, 63))):
        d.ellipse((14 + i * 20, 10, 26 + i * 20, 22), fill=c)
    for row, text in enumerate(lines[-ROWS:]):
        y = BAR + PAD + row * LH
        x0 = PAD
        if text.startswith('$ '):
            d.text((x0, y), '$', font=f, fill=GREEN)
            d.text((x0 + 2 * CW, y), text[2:], font=f, fill=FG)
            continue
        d.text((x0, y), text, font=f, fill=FG)
        for pat, col in RULES:  # repaint matched spans in colour, on the same monospace grid
            for m in re.finditer(pat, text):
                d.text((x0 + m.start() * CW, y), m.group(), font=f, fill=col)
    if cursor:
        row = min(len(lines), ROWS) - 1
        x = PAD + len(lines[-1]) * CW if lines else PAD
        d.rectangle((x, BAR + PAD + row * LH + 2, x + CW - 1, BAR + PAD + row * LH + LH - 2), fill=FG)
    return im


def main(src, out):
    f, frames, durs, lines = font(), [], [], []
    for t in open(src, encoding='utf-8').read().rstrip('\n').split('\n'):
        if t.startswith('$ '):  # type the command
            lines += [''] * bool(lines) + ['$ ']  # blank line between commands
            for i in range(len(t) - 1):
                lines[-1] = t[:i + 2]
                frames.append(draw(lines, True, f)); durs.append(55 if i else 700)
            continue
        for part in textwrap.wrap(t, COLS, drop_whitespace=False) or ['']:  # output scrolls in
            lines.append(part)
            frames.append(draw(lines, False, f)); durs.append(90 if part.strip() else 40)
    durs[-1] = 6000
    frames[0].save(out, save_all=True, append_images=frames[1:], duration=durs, loop=0, optimize=True)
    print(out, len(frames), 'frames')


if __name__ == '__main__':
    main(*sys.argv[1:])
