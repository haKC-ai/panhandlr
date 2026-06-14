"""
geo_extractor.py

Extracts mappable geographic data from:
  - Image EXIF GPS tags (lat/lon/alt)
  - Source post/page text (coordinates, addresses, city/country mentions)

Outputs GeoJSON FeatureCollection for map visualization (Leaflet, Mapbox, etc).

Called by url2ioc.py after scraping; can also run standalone against existing
analysis HTML files.
"""
import io
import json
import logging
import os
import re
import requests
from datetime import datetime, timezone
from urllib.parse import urljoin
from bs4 import BeautifulSoup
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import exifread

logger = logging.getLogger(__name__)

REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    )
}
REQUEST_TIMEOUT = 10
IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".tiff", ".tif", ".heic"}

# ── coordinate extraction patterns ─────────────────────────────────────────

# Decimal degrees: 37.4219999, -122.0840575
_DECIMAL_COORD = re.compile(
    r"\b(?P<lat>-?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?))\s*,\s*"
    r"(?P<lon>-?(?:1[0-7]\d(?:\.\d+)?|(?:[1-9]?\d(?:\.\d+)?)|180(?:\.0+)?))\b"
)

# DMS: 37°25'19.9"N 122°05'02.6"W
_DMS_COORD = re.compile(
    r"(?P<latD>\d{1,3})[°\s]\s*(?P<latM>\d{1,2})['′\s]\s*(?P<latS>\d{1,2}(?:\.\d+)?)[\"″\s]*"
    r"(?P<latH>[NS])\s*[,\s]+\s*"
    r"(?P<lonD>\d{1,3})[°\s]\s*(?P<lonM>\d{1,2})['′\s]\s*(?P<lonS>\d{1,2}(?:\.\d+)?)[\"″\s]*"
    r"(?P<lonH>[EW])"
)

# Geo URI: geo:37.786971,-122.399677
_GEO_URI = re.compile(r"geo:(?P<lat>-?\d+\.\d+),(?P<lon>-?\d+\.\d+)")

# Common location phrases  e.g. "located in Berlin, Germany" / "based in Seattle"
_LOCATION_PHRASE = re.compile(
    r"(?:located in|based in|operating from|origin[ating]+ (?:in|from)|posted from|"
    r"registered in|hosted in|server in|C2 in)\s+([A-Z][a-zA-Z ]{2,50})",
    re.IGNORECASE,
)


# ── EXIF GPS helpers ────────────────────────────────────────────────────────

def _rational_to_float(rational) -> float:
    """Convert EXIF rational (tuple or IFDRational) to float."""
    if isinstance(rational, tuple):
        return rational[0] / rational[1] if rational[1] else 0.0
    return float(rational)


def _dms_to_decimal(dms_values, ref: str) -> float | None:
    """Convert DMS EXIF tuple to decimal degrees."""
    try:
        d = _rational_to_float(dms_values[0])
        m = _rational_to_float(dms_values[1])
        s = _rational_to_float(dms_values[2])
        result = d + m / 60 + s / 3600
        if ref in ("S", "W"):
            result = -result
        return result
    except Exception:
        return None


def extract_gps_from_exif_pillow(data: bytes) -> dict | None:
    """Extract GPS lat/lon/alt from EXIF via Pillow."""
    try:
        img = Image.open(io.BytesIO(data))
        raw = img._getexif()
        if not raw:
            return None
        gps_info = raw.get(34853)  # GPSInfo tag
        if not gps_info:
            return None
        gps = {GPSTAGS.get(k, k): v for k, v in gps_info.items()}

        lat = _dms_to_decimal(gps.get("GPSLatitude"), gps.get("GPSLatitudeRef", "N"))
        lon = _dms_to_decimal(gps.get("GPSLongitude"), gps.get("GPSLongitudeRef", "E"))
        if lat is None or lon is None:
            return None

        result: dict = {"lat": lat, "lon": lon}
        alt_raw = gps.get("GPSAltitude")
        if alt_raw is not None:
            result["alt_m"] = round(_rational_to_float(alt_raw), 2)
        return result

    except Exception:
        return None


def extract_gps_from_exif_exifread(data: bytes) -> dict | None:
    """Extract GPS lat/lon/alt from EXIF via exifread (broader format support)."""
    try:
        tags = exifread.process_file(io.BytesIO(data), details=True)

        def _parse_ifdrat(tag_key: str) -> list[float] | None:
            tag = tags.get(tag_key)
            if not tag:
                return None
            vals = tag.values
            return [v.num / v.den if v.den else 0.0 for v in vals]

        lat_vals = _parse_ifdrat("GPS GPSLatitude")
        lon_vals = _parse_ifdrat("GPS GPSLongitude")
        if not lat_vals or not lon_vals:
            return None

        lat_ref = str(tags.get("GPS GPSLatitudeRef", "N"))
        lon_ref = str(tags.get("GPS GPSLongitudeRef", "E"))

        lat = lat_vals[0] + lat_vals[1] / 60 + lat_vals[2] / 3600
        lon = lon_vals[0] + lon_vals[1] / 60 + lon_vals[2] / 3600
        if "S" in lat_ref:
            lat = -lat
        if "W" in lon_ref:
            lon = -lon

        result: dict = {"lat": round(lat, 7), "lon": round(lon, 7)}
        alt_tag = tags.get("GPS GPSAltitude")
        if alt_tag:
            v = alt_tag.values[0]
            result["alt_m"] = round(v.num / v.den if v.den else 0.0, 2)
        return result

    except Exception:
        return None


# ── text coordinate extraction ──────────────────────────────────────────────

def extract_coords_from_text(text: str) -> list[dict]:
    """
    Extract all coordinate mentions from text.
    Returns list of {lat, lon, source_type, raw}.
    """
    hits: list[dict] = []

    for m in _GEO_URI.finditer(text):
        hits.append({
            "lat": float(m.group("lat")),
            "lon": float(m.group("lon")),
            "source_type": "geo_uri",
            "raw": m.group(0),
        })

    for m in _DMS_COORD.finditer(text):
        lat = (float(m.group("latD")) + float(m.group("latM")) / 60 +
               float(m.group("latS")) / 3600)
        lon = (float(m.group("lonD")) + float(m.group("lonM")) / 60 +
               float(m.group("lonS")) / 3600)
        if m.group("latH") == "S":
            lat = -lat
        if m.group("lonH") == "W":
            lon = -lon
        hits.append({"lat": round(lat, 7), "lon": round(lon, 7),
                     "source_type": "dms_text", "raw": m.group(0)})

    for m in _DECIMAL_COORD.finditer(text):
        lat, lon = float(m.group("lat")), float(m.group("lon"))
        if -90 <= lat <= 90 and -180 <= lon <= 180:
            hits.append({"lat": lat, "lon": lon,
                         "source_type": "decimal_text", "raw": m.group(0)})

    return hits


def extract_location_mentions(text: str) -> list[str]:
    """Extract named location mentions from text."""
    return [m.group(1).strip() for m in _LOCATION_PHRASE.finditer(text)]


# ── image pipeline ──────────────────────────────────────────────────────────

def _fetch_bytes(url: str) -> bytes | None:
    try:
        r = requests.get(url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        if "image" not in r.headers.get("Content-Type", ""):
            return None
        return r.content
    except Exception:
        return None


def scan_images_for_gps(page_url: str, html: str) -> list[dict]:
    """
    Extract images from page, read GPS EXIF from each.
    Returns list of GeoJSON-ready feature dicts.
    """
    soup = BeautifulSoup(html, "html.parser")
    features: list[dict] = []

    for tag in soup.find_all("img", src=True):
        src = tag["src"].strip()
        if not src or src.startswith("data:"):
            continue
        img_url = urljoin(page_url, src)
        ext = os.path.splitext(img_url.split("?")[0])[1].lower()
        if ext not in IMAGE_EXTENSIONS:
            continue

        data = _fetch_bytes(img_url)
        if not data:
            continue

        gps = extract_gps_from_exif_pillow(data) or extract_gps_from_exif_exifread(data)
        if not gps:
            continue

        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [gps["lon"], gps["lat"]] + ([gps["alt_m"]] if "alt_m" in gps else []),
            },
            "properties": {
                "source": "image_exif",
                "image_url": img_url,
                "page_url": page_url,
                "alt_m": gps.get("alt_m"),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        })

    return features


# ── main extraction entry point ─────────────────────────────────────────────

def extract_geo(page_url: str, page_text: str, html: str | None = None) -> dict:
    """
    Full geo extraction pass for one URL.
    Returns a GeoJSON FeatureCollection.
    """
    features: list[dict] = []

    # Coordinates embedded in text
    for coord in extract_coords_from_text(page_text):
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [coord["lon"], coord["lat"]],
            },
            "properties": {
                "source": coord["source_type"],
                "raw": coord["raw"],
                "page_url": page_url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        })

    # Named location mentions (no coordinates — logged as properties only)
    mentions = extract_location_mentions(page_text)

    # GPS EXIF from images
    if html:
        features.extend(scan_images_for_gps(page_url, html))

    return {
        "type": "FeatureCollection",
        "metadata": {
            "source_url": page_url,
            "extracted_at": datetime.now(timezone.utc).isoformat(),
            "location_mentions": mentions,
        },
        "features": features,
    }


def append_to_geojson(collection: dict, output_path: str) -> None:
    """Merge new FeatureCollection into the master output GeoJSON file."""
    existing: dict = {
        "type": "FeatureCollection",
        "metadata": {"sources": []},
        "features": [],
    }
    if os.path.exists(output_path):
        try:
            with open(output_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        except Exception:
            pass

    existing["features"].extend(collection.get("features", []))
    existing.setdefault("metadata", {}).setdefault("sources", []).append(
        collection.get("metadata", {})
    )

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2)


# ── standalone CLI ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="geo_extractor — extract mappable data from URLs")
    parser.add_argument("--url", required=True, help="URL to scan")
    parser.add_argument("--output", default="analysis/geo_intelligence.geojson")
    args = parser.parse_args()

    import sys
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")

    try:
        r = requests.get(args.url, headers=REQUEST_HEADERS, timeout=REQUEST_TIMEOUT)
        html = r.text
        text = BeautifulSoup(html, "html.parser").get_text(" ", strip=True)
    except Exception as e:
        print(f"[!] Failed to fetch {args.url}: {e}", file=sys.stderr)
        sys.exit(1)

    result = extract_geo(args.url, text, html)
    append_to_geojson(result, args.output)
    print(f"[+] {len(result['features'])} geo features extracted → {args.output}")
