# OG renderer fonts

These files are pinned build inputs for `src/og_image.rs`; the renderer never
downloads or discovers fonts at runtime. `NotoSans*` and the CJK collection are
copies from the Noto packages installed in the Bullnym development image.
Their package copyright notices are included beside them.

`NotoEmoji-Variable.ttf` is the monochrome Noto Emoji variable font retrieved
from the official Google Fonts repository on 2026-07-11:

`https://raw.githubusercontent.com/google/fonts/main/ofl/notoemoji/NotoEmoji%5Bwght%5D.ttf`

Selected integrity hashes:

- `NotoSans-Regular.ttf`: `89c3c497f618fdaa0b2d1e98fef93582f28c71debd2c4a8cdf41f190ced2909d`
- `NotoSansCJK-Regular.ttc`: `b76b0433203017ca80401b2ee0dd69350349871c4b19d504c34dbdd80541690a`
- `NotoEmoji-Variable.ttf`: `de6c18832938afc99caf132b39d6a30a19bac7f2e812e28db2535b4608d27551`

Any font, logo, layout, color, or encoding change must bump
`og_image::TEMPLATE_VERSION` so previously shared immutable image URLs remain
valid.
