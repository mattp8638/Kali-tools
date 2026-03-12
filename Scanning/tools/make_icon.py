"""Create a multi-size ICO from a PNG.

Usage:
  - Place your `scanner.png` image in the `Scanning` folder (next to `scanning.spec`).
  - From the `Scanning` folder run:
      python .\tools\make_icon.py .\scanner.png .\scanner.ico

This script requires Pillow: `pip install pillow`.
"""
from PIL import Image
import sys
from pathlib import Path

def make_ico(src_path: Path, out_path: Path, sizes=(16,32,48,64,128,256)):
    img = Image.open(src_path).convert("RGBA")
    # Ensure we have a square canvas for large sizes by padding
    max_size = max(img.size)
    if img.size[0] != img.size[1]:
        canvas = Image.new("RGBA", (max_size, max_size), (0,0,0,0))
        offset = ((max_size - img.size[0])//2, (max_size - img.size[1])//2)
        canvas.paste(img, offset)
        img = canvas

    # Resize copies for each requested size
    icons = [img.resize((s,s), Image.LANCZOS) for s in sizes]
    # Save as ICO (Pillow will embed multiple sizes)
    icons[0].save(out_path, format='ICO', sizes=[(s,s) for s in sizes])

def main():
    if len(sys.argv) < 3:
        print("Usage: python make_icon.py <input.png> <output.ico>")
        return 1
    src = Path(sys.argv[1])
    out = Path(sys.argv[2])
    if not src.exists():
        print(f"Input not found: {src}")
        return 2
    try:
        make_ico(src, out)
        print(f"Wrote: {out.resolve()}")
        return 0
    except Exception as e:
        print(f"Failed to create ico: {e}")
        return 3

if __name__ == '__main__':
    raise SystemExit(main())
