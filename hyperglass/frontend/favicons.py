"""Generate the favicon set from a single source image.

The UI references a fixed list of icon files (see `FAVICON_FORMATS` and
`hyperglass/ui/favicon-formats.ts`). Each is the source image scaled to fit,
centred on a transparent canvas.
"""

# Standard Library
import math
import typing as t
from io import BytesIO
from pathlib import Path

if t.TYPE_CHECKING:
    # Third Party
    from PIL.Image import Image

SUPPORTED_SOURCE_FORMATS = (".svg", ".jpeg", ".jpg", ".png", ".tiff", ".tif")

# Width the SVG source is rasterised to before scaling down. Larger than the
# largest icon so every size is a downscale.
SVG_RENDER_WIDTH = 1024


class FaviconFormat(t.TypedDict):
    """One generated favicon file, as the UI describes it."""

    dimensions: t.Tuple[int, int]
    image_format: str
    prefix: str
    rel: t.Optional[str]


def _format(
    prefix: str, width: int, height: int, rel: t.Optional[str], image_format: str = "png"
) -> FaviconFormat:
    return {
        "dimensions": (width, height),
        "image_format": image_format,
        "prefix": prefix,
        "rel": rel,
    }


FAVICON_FORMATS: t.Tuple[FaviconFormat, ...] = (
    _format("favicon", 64, 64, None, "ico"),
    *(_format("favicon", size, size, "icon") for size in (16, 32, 64, 96, 180)),
    *(
        _format("apple-touch-icon", size, size, "apple-touch-icon")
        for size in (57, 60, 72, 76, 114, 120, 144, 152, 167, 180)
    ),
    *(
        _format("mstile", width, height, None)
        for width, height in ((70, 70), (270, 270), (310, 310), (310, 150))
    ),
    _format("favicon", 196, 196, "shortcut icon"),
)


def favicon_filename(favicon: FaviconFormat) -> str:
    """Get the file name the UI requests for a favicon format."""
    if favicon["image_format"] == "ico":
        return f"{favicon['prefix']}.ico"
    width, height = favicon["dimensions"]
    return f"{favicon['prefix']}-{width}x{height}.{favicon['image_format']}"


def favicon_formats() -> t.Tuple[t.Dict[str, t.Any], ...]:
    """Get the favicon formats in the shape written to `favicon-formats.ts`."""
    return tuple(
        {**favicon, "dimensions": list(favicon["dimensions"])} for favicon in FAVICON_FORMATS
    )


def _render_svg(source: Path) -> "Image":
    """Rasterise an SVG to an RGBA image with a transparent background."""
    # Third Party
    from PIL import Image
    from svglib.svglib import svg2rlg
    from reportlab.graphics import renderPM

    drawing = svg2rlg(str(source))
    if drawing is None:
        raise ValueError(f"'{source!s}' could not be read as an SVG image")

    if drawing.width and drawing.height:
        scale = SVG_RENDER_WIDTH / drawing.width
        drawing.width, drawing.height = drawing.width * scale, drawing.height * scale
        drawing.scale(scale, scale)

    # reportlab renders onto an opaque canvas. Render on two backgrounds and
    # recover coverage from the difference, so the icon keeps its transparency
    # and anti-aliased edges.
    on_white = Image.open(BytesIO(renderPM.drawToString(drawing, fmt="PNG", bg=0xFFFFFF)))
    on_black = Image.open(BytesIO(renderPM.drawToString(drawing, fmt="PNG", bg=0x000000)))
    return _recover_alpha(on_white.convert("RGB"), on_black.convert("RGB"))


def _recover_alpha(on_white: "Image", on_black: "Image") -> "Image":
    """Combine renders on white and on black into one RGBA image.

    For a pixel with colour `c` and coverage `a`: white = c*a + 255*(1 - a) and
    black = c*a, so a = 1 - (white - black) / 255 and c = black / a.
    """
    # Third Party
    from PIL import Image, ImageMath, ImageChops

    difference = ImageChops.difference(on_white, on_black).convert("L")
    alpha = ImageChops.invert(difference)

    def unpremultiply(args: t.Dict[str, t.Any]) -> t.Any:
        colour, coverage = args["float"](args["c"]), args["float"](args["a"])
        return args["convert"](args["min"](colour * 255 / args["max"](coverage, 1), 255), "L")

    channels = [ImageMath.lambda_eval(unpremultiply, c=c, a=alpha) for c in on_black.split()]
    return Image.merge("RGBA", (*channels, alpha))


def load_source(source: Path) -> "Image":
    """Open the source image as RGBA, rasterising it first if it is an SVG."""
    # Third Party
    from PIL import Image

    suffix = source.suffix.lower()
    if suffix not in SUPPORTED_SOURCE_FORMATS:
        supported = ", ".join(SUPPORTED_SOURCE_FORMATS)
        raise ValueError(f"Favicon '{source!s}' is not a supported format ({supported})")

    if suffix == ".svg":
        return _render_svg(source)

    with Image.open(source) as image:
        return image.convert("RGBA")


def _fit(source: "Image", dimensions: t.Tuple[int, int]) -> "Image":
    """Scale the source to fit `dimensions` and centre it on a transparent canvas."""
    # Third Party
    from PIL import Image

    scaled = source.copy()
    scaled.thumbnail(dimensions)
    canvas = Image.new("RGBA", dimensions, (0, 0, 0, 0))
    left = math.floor((dimensions[0] - scaled.width) / 2)
    top = math.floor((dimensions[1] - scaled.height) / 2)
    canvas.paste(scaled, (left, top))
    return canvas


def generate_favicons(source: Path, output_directory: Path) -> int:
    """Write every favicon format for `source` into `output_directory`.

    Returns the number of files written.
    """
    output_directory.mkdir(parents=True, exist_ok=True)
    image = load_source(Path(source))
    written = 0
    for favicon in FAVICON_FORMATS:
        icon = _fit(image, tuple(favicon["dimensions"]))
        icon.save(output_directory / favicon_filename(favicon), favicon["image_format"])
        written += 1
    return written
