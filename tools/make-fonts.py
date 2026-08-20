"""Cut the two static weights the interface uses from the variable Archivo.

    python tools/make-fonts.py

Run by hand; the two files it writes are committed beside the variable font.

**This exists because `ab_glyph` does not apply variation axes.** egui
rasterises with it, so registering `Archivo.ttf` draws whatever outlines are
stored as the default instance -- which for this font is SemiBold. Muster's
whole interface was therefore 600, body copy included, and no amount of asking
for a lighter weight would have changed it. Two static instances is the only
way to have the two weights section 4 of the style guide allows.

The variable font stays in the tree: it is what the wordmark is drawn from, and
`examples/make-art.rs` reads it through skrifa, which *does* apply axes.
"""

import pathlib

from fontTools.ttLib import TTFont
from fontTools.varLib import instancer

ASSETS = pathlib.Path(__file__).resolve().parent.parent / "crates/muster-app/assets"
SOURCE = ASSETS / "Archivo.ttf"

# The two ranks section 4 permits, and nothing between them.
WEIGHTS = {400: "Archivo-Regular.ttf", 600: "Archivo-SemiBold.ttf"}


def main() -> None:
    for weight, name in WEIGHTS.items():
        font = TTFont(SOURCE)
        # Both axes pinned: a width left variable would leave the instancer
        # emitting variation tables that ab_glyph then ignores, which is the
        # situation this script exists to get out of.
        instancer.instantiateVariableFont(
            font, {"wght": weight, "wdth": 100}, inplace=True
        )
        font.save(ASSETS / name)
        print(f"  {name}")


if __name__ == "__main__":
    main()
