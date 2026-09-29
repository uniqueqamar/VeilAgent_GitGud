"""
Playwright Synthetic UI Dataset Generator and Auto-Labeler
Renders dev and held-out templates across viewports, zooms, themes, and fonts.
Auto-extracts ground truth bounding boxes and class labels from DOM.
Splits strictly by TEMPLATE (Invariant & Task 2).
"""

import json
import os
import time
from pathlib import Path
from playwright.sync_api import sync_playwright

CLASSES = [
    "button",
    "text_input",
    "checkbox",
    "radio",
    "dropdown",
    "link",
    "icon",
    "image",
    "table",
    "label",
    "dialog"
]

VIEWPORTS = [
    {"width": 1280, "height": 800},
    {"width": 1920, "height": 1080},
    {"width": 800, "height": 600}
]

ZOOMS = [0.75, 1.0, 1.25, 1.5]
THEMES = ["light", "dark"]
FONTS = ["system-ui, sans-serif", "Georgia, serif", "Courier New, monospace"]

DOM_EXTRACT_SCRIPT = """
(() => {
    const results = [];
    const vw = window.innerWidth;
    const vh = window.innerHeight;

    function getBox(el) {
        const r = el.getBoundingClientRect();
        return [
            Math.round(r.left),
            Math.round(r.top),
            Math.round(r.width),
            Math.round(r.height)
        ];
    }

    function isVisible(el, box) {
        const [x, y, w, h] = box;
        if (w < 8 || h < 8) return false;
        if (x + w < 0 || y + h < 0 || x > vw || y > vh) return false;
        const s = window.getComputedStyle(el);
        if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return false;
        return true;
    }

    // 1. Buttons
    const buttons = document.querySelectorAll('button, input[type="button"], input[type="submit"], input[type="reset"], [role="button"]');
    buttons.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'button', box, id: el.id || '' });
    });

    // 2. Text Inputs
    const textInputs = document.querySelectorAll('input[type="text"], input[type="email"], input[type="search"], input[type="tel"], input[type="password"], textarea, [role="textbox"]');
    textInputs.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'text_input', box, id: el.id || '' });
    });

    // 3. Checkboxes
    const checkboxes = document.querySelectorAll('input[type="checkbox"], [role="checkbox"]');
    checkboxes.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'checkbox', box, id: el.id || '' });
    });

    // 4. Radios
    const radios = document.querySelectorAll('input[type="radio"], [role="radio"]');
    radios.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'radio', box, id: el.id || '' });
    });

    // 5. Dropdowns
    const dropdowns = document.querySelectorAll('select, [role="combobox"], [role="listbox"]');
    dropdowns.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'dropdown', box, id: el.id || '' });
    });

    // 6. Links
    const links = document.querySelectorAll('a[href], [role="link"]');
    links.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'link', box, id: el.id || '' });
    });

    // 7. Icons
    const icons = document.querySelectorAll('svg.icon, i.icon, [data-icon]');
    icons.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'icon', box, id: el.id || '' });
    });

    // 8. Images
    const images = document.querySelectorAll('img, [role="img"], picture');
    images.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'image', box, id: el.id || '' });
    });

    // 9. Tables
    const tables = document.querySelectorAll('table, [role="table"], [role="grid"]');
    tables.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'table', box, id: el.id || '' });
    });

    // 10. Labels
    const labels = document.querySelectorAll('label, .kpi-label, .metric-title');
    labels.forEach(el => {
        // Only standalone labels not containing inputs
        if (!el.querySelector('input, select')) {
            const box = getBox(el);
            if (isVisible(el, box)) results.push({ class: 'label', box, id: el.id || '' });
        }
    });

    // 11. Dialogs
    const dialogs = document.querySelectorAll('dialog, [role="dialog"], .dialog-box, .modal');
    dialogs.forEach(el => {
        const box = getBox(el);
        if (isVisible(el, box)) results.push({ class: 'dialog', box, id: el.id || '' });
    });

    // Canvas custom widgets ground truth if present on canvas pages
    const canvas = document.getElementById('app-canvas');
    if (canvas && window.widgets) {
        const cr = canvas.getBoundingClientRect();
        for (const [wName, w] of Object.entries(window.widgets)) {
            const box = [
                Math.round(cr.left + w.x),
                Math.round(cr.top + w.y),
                Math.round(w.w),
                Math.round(w.h)
            ];
            results.push({ class: w.class, box, id: 'canvas_' + wName, isCanvasWidget: true });
        }
    }

    return results;
})();
"""

def render_dataset(output_base_dir="eval/ui_data", max_per_template=12):
    base_path = Path(output_base_dir)
    train_dir = base_path / "train"
    held_out_dir = base_path / "held_out"
    train_dir.mkdir(parents=True, exist_ok=True)
    held_out_dir.mkdir(parents=True, exist_ok=True)

    templates_dir = Path("eval/synthetic_pages/ui_templates")
    dev_templates = list((templates_dir / "dev").glob("*.html"))
    held_out_templates = list((templates_dir / "held_out").glob("*.html"))

    print(f"Discovered {len(dev_templates)} dev templates and {len(held_out_templates)} held-out templates.")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # Process splits
        splits = [
            ("train", dev_templates, train_dir),
            ("held_out", held_out_templates, held_out_dir)
        ]

        total_samples = 0
        total_boxes = 0

        for split_name, templates, dest_dir in splits:
            print(f"\n--- Generating {split_name} split (Split by TEMPLATE) ---")
            for tmpl_path in templates:
                tmpl_name = tmpl_path.stem
                sample_idx = 0
                file_url = f"file:///{tmpl_path.resolve().as_posix()}"

                # Generate variations
                for vp in VIEWPORTS:
                    for zoom in ZOOMS:
                        for theme in THEMES:
                            font = FONTS[sample_idx % len(FONTS)]
                            sample_idx += 1
                            if sample_idx > max_per_template:
                                break

                            sample_id = f"{tmpl_name}_vp{vp['width']}x{vp['height']}_z{int(zoom*100)}_{theme}_{sample_idx}"
                            img_file = dest_dir / f"{sample_id}.png"
                            json_file = dest_dir / f"{sample_id}.json"

                            page = browser.new_page(viewport=vp)
                            try:
                                page.goto(file_url, wait_until="networkidle")

                                # Apply variations
                                page.evaluate(f"""
                                    document.body.style.zoom = '{zoom}';
                                    if ('{theme}' === 'dark') {{
                                        document.body.classList.add('dark-theme');
                                    }} else {{
                                        document.body.classList.remove('dark-theme');
                                    }}
                                    document.body.style.fontFamily = '{font}';
                                """)
                                page.wait_for_timeout(60)

                                # Extract ground-truth DOM boxes
                                gt_elements = page.evaluate(DOM_EXTRACT_SCRIPT)

                                # Capture screenshot
                                page.screenshot(path=str(img_file))

                                # Write metadata
                                meta = {
                                    "sample_id": sample_id,
                                    "template": tmpl_name,
                                    "split": split_name,
                                    "viewport": [vp["width"], vp["height"]],
                                    "zoom": zoom,
                                    "theme": theme,
                                    "font": font,
                                    "image": img_file.name,
                                    "elements": gt_elements
                                }
                                with open(json_file, "w", encoding="utf-8") as f:
                                    json.dump(meta, f, indent=2)

                                total_samples += 1
                                total_boxes += len(gt_elements)
                            finally:
                                page.close()

                            if sample_idx >= max_per_template:
                                break
                        if sample_idx >= max_per_template:
                            break
                    if sample_idx >= max_per_template:
                        break

                print(f"  Template {tmpl_name}: Generated {sample_idx} variations.")

        browser.close()

    print(f"\nDataset generation complete: {total_samples} samples, {total_boxes} ground-truth boxes.")
    return total_samples, total_boxes

if __name__ == "__main__":
    render_dataset()
