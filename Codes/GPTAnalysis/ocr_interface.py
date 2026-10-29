# -*- coding: utf-8 -*-

"""Tesseract OCR wrapper."""

import argparse
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, List, Optional


class TesseractOCR:
    """Thin wrapper around the tesseract binary."""

    def __init__(self, lang: str = "eng", extra_args: Optional[Iterable[str]] = None):
        """Set the language and extra tesseract arguments."""
        self.tesseract_bin = shutil.which("tesseract")
        if not self.tesseract_bin:
            raise RuntimeError("tesseract binary not found. Please install Tesseract OCR.")
        self.lang = lang
        self.extra_args = list(extra_args) if extra_args else []

    def recognize(self, image_path: str, lang: Optional[str] = None) -> str:
        """Run OCR on an image and return the text."""
        image = Path(image_path).expanduser().resolve()
        if not image.exists():
            raise FileNotFoundError(f"Image not found: {image}")

        args: List[str] = [self.tesseract_bin, str(image), "stdout"]
        lang_to_use = lang or self.lang
        if lang_to_use:
            args.extend(["-l", lang_to_use])
        if self.extra_args:
            args.extend(self.extra_args)

        try:
            result = subprocess.run(
                args,
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr.strip() if exc.stderr else "no stderr"
            raise RuntimeError(f"Tesseract OCR failed: {stderr}") from exc

        return result.stdout.strip()


def _build_arg_parser() -> argparse.ArgumentParser:
    """Build the command line parser."""
    parser = argparse.ArgumentParser(description="Run OCR via Tesseract.")
    parser.add_argument("image", help="Path to the image to be processed.")
    parser.add_argument(
        "--lang",
        default="eng",
        help="Language pack passed to Tesseract (default: eng).",
    )
    parser.add_argument(
        "--extra",
        nargs="*",
        default=None,
        help="Additional raw arguments forwarded to tesseract.",
    )
    return parser


def main() -> None:
    """Command line entry point."""
    parser = _build_arg_parser()
    args = parser.parse_args()
    ocr = TesseractOCR(lang=args.lang, extra_args=args.extra)
    print(ocr.recognize(args.image, lang=args.lang))


if __name__ == "__main__":
    main()

