# Dataset Licenses & Provenance: Veil Vision Evaluation Corpus

All images, documents, face crops, and media in `eval/vision_data/` and `eval/vision_pages/` are strictly synthetic, procedurally generated, or released under permissive open-source / public domain licenses. No real private personal data, non-consensual face photographs, or proprietary copyrighted assets are included.

---

## 1. Synthetic Identity Documents (`eval/vision_data/ids/`)
- **Generator**: Procedural Python generator (`eval/gen_vision_data.py`) using PIL / Pillow.
- **Watermark**: All documents are indelibly stamped `"SAMPLE - SYNTHETIC"` across the foreground.
- **Numbers & Data**: All identity numbers (Aadhaar, PAN, Card, Mobile, Account, IFSC) are algorithmically synthesized using standard Verhoeff and Luhn checksum generators with fictional prefixes. None correspond to living individuals.
- **Fonts**:
  - `Noto Sans Devanagari` / `Nirmala UI`: Licensed under the SIL Open Font License (OFL) v1.1.
  - `Liberation Sans` / `DejaVu Sans` / `Arial`: Used for synthetic document layout and text rendering.
- **License**: Creative Commons Zero (CC0 1.0) Public Domain Dedication.

---

## 2. Face Assets (`eval/vision_data/faces/`)
- **Source**: Procedural composite facial portraits synthesized via SVG / Canvas / PIL vector rendering and open AI-synthesized face generators.
- **Attributes**: Varied ages (child, young adult, elder), diverse skin tones, accessories (eyeglasses, surgical/N95 masks), side profiles, and multi-subject group shots with small faces.
- **Consented / Synthetic Rights**: Fully synthetic assets generated specifically for privacy benchmark evaluation. No likeness of non-consenting individuals is utilized.
- **License**: CC0 1.0 Public Domain / MIT License.

---

## 3. Hard Negatives (`eval/vision_data/hard_negatives/`)
- **Categories**:
  - **Animals**: Procedural silhouettes and synthetic animal portraits (CC0).
  - **Statues & Sculptures**: Classical public-domain historical sculpture renders (CC0).
  - **Cartoons & Logos**: Abstract geometric vector icons and fictional corporate logos (MIT / CC0).
  - **Posters & Scenery**: Synthetic gradient landscapes and architectural vectors (CC0).
  - **Non-PII Text**: Public domain legal statutes, recipe text, and mathematical tables without personal information (CC0).
  - **Checksum-Invalid Numerical Pages**: Dense tables of random numbers deliberately engineered to fail Luhn and Verhoeff checksums.
- **License**: CC0 1.0 Universal.

---

## 4. Evaluation Web Pages (`eval/vision_pages/`)
- **Pages**: 60 Dev pages (`dev_001.html` through `dev_060.html`) and 40 Held-Out pages (`held_out_001.html` through `held_out_040.html`).
- **Embedding Modes**: Native HTML `<img>`, `<canvas>` draw operations, CSS `background-image` declarations, `<video>` poster frames, and simulated `<iframe>`/`<embed>` PDF viewer containers.
- **Ground Truth**: Stored in `eval/vision_data/ground_truth.json` specifying exact bounding boxes `[x, y, w, h]` for all faces and PII word boundaries.
- **License**: Apache-2.0 / CC0.
