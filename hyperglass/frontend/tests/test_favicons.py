"""Favicon generation must keep producing the files the UI asks for."""

# Standard Library
import json
from pathlib import Path
from collections import OrderedDict

# Third Party
import pytest
from PIL import Image

# Local
from ..favicons import (
    FAVICON_FORMATS,
    load_source,
    favicon_formats,
    favicon_filename,
    generate_favicons,
)

REPO_PACKAGE = Path(__file__).resolve().parents[2]
DEFAULT_ICON = REPO_PACKAGE / "images" / "hyperglass-icon.svg"

EXPECTED_FILES = {
    "favicon.ico",
    "favicon-16x16.png",
    "favicon-32x32.png",
    "favicon-64x64.png",
    "favicon-96x96.png",
    "favicon-180x180.png",
    "favicon-196x196.png",
    "apple-touch-icon-57x57.png",
    "apple-touch-icon-60x60.png",
    "apple-touch-icon-72x72.png",
    "apple-touch-icon-76x76.png",
    "apple-touch-icon-114x114.png",
    "apple-touch-icon-120x120.png",
    "apple-touch-icon-144x144.png",
    "apple-touch-icon-152x152.png",
    "apple-touch-icon-167x167.png",
    "apple-touch-icon-180x180.png",
    "mstile-70x70.png",
    "mstile-270x270.png",
    "mstile-310x310.png",
    "mstile-310x150.png",
}


def test_formats_match_the_file_the_ui_imports():
    """`favicon-formats.ts` is committed; the generator must agree with it."""
    ordered = json.dumps([OrderedDict(sorted(f.items())) for f in favicon_formats()])
    committed = (REPO_PACKAGE / "ui" / "favicon-formats.ts").read_text()
    assert ordered in committed


def test_file_names():
    assert {favicon_filename(f) for f in FAVICON_FORMATS} == EXPECTED_FILES


def test_svg_source_generates_every_file_at_its_size(tmp_path):
    assert generate_favicons(DEFAULT_ICON, tmp_path) == len(EXPECTED_FILES)
    assert {p.name for p in tmp_path.iterdir()} == EXPECTED_FILES
    for favicon in FAVICON_FORMATS:
        with Image.open(tmp_path / favicon_filename(favicon)) as image:
            assert image.size == tuple(favicon["dimensions"])
            assert image.format == ("ICO" if favicon["image_format"] == "ico" else "PNG")


def test_svg_is_rendered_with_a_transparent_background():
    image = load_source(DEFAULT_ICON)
    assert image.mode == "RGBA"
    alpha = image.getchannel("A")
    # Corners are outside the artwork; the artwork itself is opaque somewhere.
    assert alpha.getpixel((0, 0)) == 0
    assert alpha.getpixel((image.width - 1, image.height - 1)) == 0
    assert alpha.getextrema() == (0, 255)


def test_non_square_raster_source_is_centred_and_not_stretched(tmp_path):
    source = tmp_path / "wide.png"
    Image.new("RGBA", (400, 200), (200, 30, 30, 255)).save(source)
    out = tmp_path / "out"
    generate_favicons(source, out)

    with Image.open(out / "favicon-64x64.png") as image:
        image = image.convert("RGBA")
        # 400x200 fits a 64x64 box as 64x32, centred: rows 16..47 are filled.
        assert image.getpixel((32, 32)) == (200, 30, 30, 255)
        assert image.getpixel((32, 4))[3] == 0
        assert image.getpixel((32, 60))[3] == 0

    with Image.open(out / "mstile-310x150.png") as image:
        image = image.convert("RGBA")
        # Fits as 300x150, centred horizontally.
        assert image.size == (310, 150)
        assert image.getpixel((155, 75)) == (200, 30, 30, 255)
        assert image.getpixel((1, 75))[3] == 0


@pytest.mark.parametrize("suffix", [".jpg", ".png", ".tiff"])
def test_raster_formats_are_accepted(tmp_path, suffix):
    source = tmp_path / f"icon{suffix}"
    Image.new("RGB", (128, 128), (10, 120, 200)).save(source)
    assert generate_favicons(source, tmp_path / "out") == len(EXPECTED_FILES)


def test_unsupported_source_is_rejected(tmp_path):
    source = tmp_path / "icon.gif"
    Image.new("RGB", (16, 16)).save(source)
    with pytest.raises(ValueError, match="not a supported format"):
        generate_favicons(source, tmp_path / "out")


def test_output_directory_is_created(tmp_path):
    target = tmp_path / "static" / "images" / "favicons"
    generate_favicons(DEFAULT_ICON, target)
    assert (target / "favicon.ico").is_file()
