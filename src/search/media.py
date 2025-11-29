"""Image and video OSINT capabilities for TR4C3R.

Reverse image search, EXIF extraction, video frame analysis, and face detection.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import httpx
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS

from src.core.data_models import Result

logger = logging.getLogger(__name__)


class ImageSearch:
    """Performs reverse image searches and metadata extraction."""

    REVERSE_SEARCH_ENGINES = {
        "google": "https://www.google.com/searchbyimage?image_url={url}",
        "yandex": "https://yandex.com/images/search?rpt=imageview&url={url}",
        "tineye": "https://tineye.com/search?url={url}",
        "bing": "https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIRP&sbisrc=UrlPaste&q=imgurl:{url}",
    }

    def __init__(self, config: Optional[Dict] = None):
        """Initialize the image search module.

        Args:
            config: Configuration dictionary with API keys and settings
        """
        self.config = config or {}
        self.client = httpx.AsyncClient(timeout=30.0)
        self.enabled_engines = self.config.get(
            "enabled_engines", list(self.REVERSE_SEARCH_ENGINES.keys())
        )
        logger.info(f"ImageSearch initialized with engines: {self.enabled_engines}")

    async def reverse_search(self, image_url: str) -> List[Result]:
        """Perform reverse image search across multiple engines.

        Args:
            image_url: URL of the image to search

        Returns:
            List of search results from various engines
        """
        logger.info(f"Performing reverse image search: {image_url}")
        results = []

        # Verify image URL is accessible
        try:
            response = await self.client.get(image_url, timeout=10.0)
            if response.status_code != 200:
                logger.warning(f"Image URL not accessible: {image_url}")
                return results
        except Exception as e:
            logger.error(f"Error accessing image URL: {e}")
            return results

        # Search on each enabled engine
        for engine in self.enabled_engines:
            if engine in self.REVERSE_SEARCH_ENGINES:
                search_url = self.REVERSE_SEARCH_ENGINES[engine].format(url=quote(image_url))

                results.append(
                    Result(
                        source=f"reverse_image_{engine}",
                        identifier=image_url,
                        url=search_url,
                        confidence=0.8,
                        metadata={
                            "engine": engine,
                            "search_type": "reverse_image",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        },
                    )
                )

        logger.info(f"Found {len(results)} reverse image search URLs")
        return results

    async def extract_metadata(self, image_url: str) -> Dict[str, Any]:
        """Extract EXIF and metadata from image.

        Args:
            image_url: URL or local path of the image

        Returns:
            Dictionary containing all extracted metadata
        """
        logger.info(f"Extracting metadata from: {image_url}")
        metadata: Dict[str, Any] = {
            "source": image_url,
            "extracted_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            # Download or load image
            if image_url.startswith(("http://", "https://")):
                response = await self.client.get(image_url, timeout=15.0)
                image_data = response.content
            else:
                with open(image_url, "rb") as f:
                    image_data = f.read()

            # Open image with PIL
            image = Image.open(io.BytesIO(image_data))

            # Basic image properties
            metadata["format"] = image.format
            metadata["mode"] = image.mode
            metadata["size"] = {"width": image.width, "height": image.height}
            metadata["file_size_bytes"] = len(image_data)

            # Calculate image hashes for deduplication
            metadata["hashes"] = {
                "md5": hashlib.md5(image_data).hexdigest(),
                "sha256": hashlib.sha256(image_data).hexdigest(),
            }

            # Extract EXIF data
            exif_data = image.getexif()
            if exif_data:
                metadata["exif"] = self._parse_exif(exif_data)

            logger.info(f"Extracted metadata: {len(metadata)} fields")
            return metadata

        except Exception as e:
            logger.error(f"Error extracting metadata: {e}", exc_info=True)
            metadata["error"] = str(e)
            return metadata

    def _parse_exif(self, exif_data) -> Dict[str, Any]:
        """Parse EXIF data into readable format.

        Args:
            exif_data: PIL EXIF data object

        Returns:
            Dictionary of parsed EXIF tags
        """
        parsed = {}

        for tag_id, value in exif_data.items():
            tag_name = TAGS.get(tag_id, tag_id)

            # Handle GPS info specially
            if tag_name == "GPSInfo":
                parsed["gps"] = self._parse_gps(value)
            else:
                # Convert bytes to string for readability
                if isinstance(value, bytes):
                    try:
                        value = value.decode("utf-8", errors="ignore")
                    except Exception:
                        value = str(value)

                parsed[tag_name] = value

        return parsed

    def _parse_gps(self, gps_info) -> Dict[str, Any]:
        """Parse GPS EXIF data into coordinates.

        Args:
            gps_info: GPS EXIF data

        Returns:
            Dictionary with GPS coordinates and metadata
        """
        gps_data = {}

        for key, value in gps_info.items():
            tag_name = GPSTAGS.get(key, key)
            gps_data[tag_name] = value

        # Extract coordinates if available
        if "GPSLatitude" in gps_data and "GPSLongitude" in gps_data:
            lat = self._convert_to_degrees(gps_data["GPSLatitude"])
            lon = self._convert_to_degrees(gps_data["GPSLongitude"])

            # Apply hemisphere
            if gps_data.get("GPSLatitudeRef") == "S":
                lat = -lat
            if gps_data.get("GPSLongitudeRef") == "W":
                lon = -lon

            gps_data["coordinates"] = {"latitude": lat, "longitude": lon}

        return gps_data

    def _convert_to_degrees(self, value) -> float:
        """Convert GPS coordinates to degrees.

        Args:
            value: GPS coordinate in degrees, minutes, seconds format

        Returns:
            Decimal degrees
        """
        d, m, s = value
        return float(d) + float(m) / 60.0 + float(s) / 3600.0

    async def search_by_hash(self, image_url: str) -> List[Result]:
        """Search for similar images by hash.

        Args:
            image_url: URL or path to image

        Returns:
            List of potential matches
        """
        logger.info(f"Searching by image hash: {image_url}")
        results = []

        try:
            metadata = await self.extract_metadata(image_url)

            if "hashes" in metadata:
                # Create results with hash information
                for hash_type, hash_value in metadata["hashes"].items():
                    results.append(
                        Result(
                            source=f"image_hash_{hash_type}",
                            identifier=hash_value,
                            url=image_url,
                            confidence=0.95,
                            metadata={
                                "hash_type": hash_type,
                                "image_size": metadata.get("size"),
                                "format": metadata.get("format"),
                            },
                        )
                    )

        except Exception as e:
            logger.error(f"Error in hash search: {e}")

        return results


class VideoSearch:
    """Performs video frame extraction and analysis."""

    def __init__(self, config: Optional[Dict] = None):
        """Initialize the video search module.

        Args:
            config: Configuration dictionary with settings
        """
        self.config = config or {}
        self.client = httpx.AsyncClient(timeout=60.0)
        logger.info("VideoSearch initialized")

    async def extract_frames(
        self, video_url: str, max_frames: int = 10, interval_seconds: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Extract frames from video for analysis.

        Args:
            video_url: URL or path to video file
            max_frames: Maximum number of frames to extract
            interval_seconds: Interval between frames (if None, evenly distribute)

        Returns:
            List of frame data dictionaries
        """
        logger.info(f"Extracting frames from video: {video_url}")
        frames = []

        try:
            # Check if opencv is available
            try:
                import cv2
            except ImportError:
                logger.error("OpenCV not installed. Run: pip install opencv-python")
                return frames

            # Download video if URL
            if video_url.startswith(("http://", "https://")):
                response = await self.client.get(video_url, timeout=30.0)

                with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
                    tmp.write(response.content)
                    video_path = tmp.name
            else:
                video_path = video_url

            # Open video
            cap = cv2.VideoCapture(video_path)

            if not cap.isOpened():
                logger.error("Failed to open video")
                return frames

            # Get video properties
            total_frames = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
            fps = cap.get(cv2.CAP_PROP_FPS)
            duration = total_frames / fps if fps > 0 else 0

            logger.info(f"Video: {total_frames} frames, {fps} FPS, {duration:.2f}s")

            # Calculate frame indices to extract
            if interval_seconds:
                frame_indices = []
                current_time = 0
                while current_time < duration and len(frame_indices) < max_frames:
                    frame_indices.append(int(current_time * fps))
                    current_time += interval_seconds
            else:
                # Evenly distribute frames
                frame_indices = [int(i * total_frames / max_frames) for i in range(max_frames)]

            # Extract frames
            for idx, frame_idx in enumerate(frame_indices):
                cap.set(cv2.CAP_PROP_POS_FRAMES, frame_idx)
                ret, frame = cap.read()

                if ret:
                    # Save frame to temp file
                    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
                        cv2.imwrite(tmp.name, frame)
                        frame_path = tmp.name

                    frames.append(
                        {
                            "frame_number": frame_idx,
                            "timestamp": frame_idx / fps if fps > 0 else 0,
                            "path": frame_path,
                            "shape": {"width": frame.shape[1], "height": frame.shape[0]},
                        }
                    )

            cap.release()
            logger.info(f"Extracted {len(frames)} frames")

        except Exception as e:
            logger.error(f"Error extracting frames: {e}", exc_info=True)

        return frames

    async def analyze_video_metadata(self, video_url: str) -> Dict[str, Any]:
        """Extract metadata from video file.

        Args:
            video_url: URL or path to video

        Returns:
            Dictionary of video metadata
        """
        logger.info(f"Analyzing video metadata: {video_url}")
        metadata: Dict[str, Any] = {
            "source": video_url,
            "extracted_at": datetime.now(timezone.utc).isoformat(),
        }

        try:
            import cv2

            # Download if URL
            if video_url.startswith(("http://", "https://")):
                response = await self.client.get(video_url, timeout=30.0)
                with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
                    tmp.write(response.content)
                    video_path = tmp.name
                    metadata["file_size_bytes"] = len(response.content)
            else:
                video_path = video_url
                metadata["file_size_bytes"] = Path(video_path).stat().st_size

            # Open video
            cap = cv2.VideoCapture(video_path)

            if cap.isOpened():
                metadata["properties"] = {
                    "frame_count": int(cap.get(cv2.CAP_PROP_FRAME_COUNT)),
                    "fps": cap.get(cv2.CAP_PROP_FPS),
                    "width": int(cap.get(cv2.CAP_PROP_FRAME_WIDTH)),
                    "height": int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT)),
                    "duration_seconds": (
                        int(cap.get(cv2.CAP_PROP_FRAME_COUNT)) / cap.get(cv2.CAP_PROP_FPS)
                        if cap.get(cv2.CAP_PROP_FPS) > 0
                        else 0
                    ),
                }

                cap.release()

        except ImportError:
            logger.warning("OpenCV not installed - limited video metadata available")
            metadata["error"] = "OpenCV not available"
        except Exception as e:
            logger.error(f"Error analyzing video: {e}", exc_info=True)
            metadata["error"] = str(e)

        return metadata


class FaceRecognition:
    """Face detection and recognition capabilities (optional)."""

    def __init__(self, config: Optional[Dict] = None):
        """Initialize face recognition module.

        Args:
            config: Configuration dictionary
        """
        self.config = config or {}
        self.enabled = self._check_dependencies()
        logger.info(f"FaceRecognition initialized (enabled={self.enabled})")

    def _check_dependencies(self) -> bool:
        """Check if face_recognition library is available.

        Returns:
            True if dependencies are available
        """
        try:
            import face_recognition

            return True
        except ImportError:
            logger.warning("face_recognition not installed. Run: pip install face_recognition")
            return False

    async def detect_faces(self, image_path: str) -> List[Dict[str, Any]]:
        """Detect faces in an image.

        Args:
            image_path: Path to image file

        Returns:
            List of detected face locations and encodings
        """
        if not self.enabled:
            logger.warning("Face recognition not available")
            return []

        logger.info(f"Detecting faces in: {image_path}")
        faces = []

        try:
            import face_recognition

            # Load image
            image = face_recognition.load_image_file(image_path)

            # Detect faces
            face_locations = face_recognition.face_locations(image)
            face_encodings = face_recognition.face_encodings(image, face_locations)

            for idx, (location, encoding) in enumerate(zip(face_locations, face_encodings)):
                top, right, bottom, left = location

                faces.append(
                    {
                        "face_id": idx,
                        "location": {
                            "top": top,
                            "right": right,
                            "bottom": bottom,
                            "left": left,
                        },
                        "encoding": encoding.tolist(),  # Convert numpy array to list
                        "area": (right - left) * (bottom - top),
                    }
                )

            logger.info(f"Detected {len(faces)} faces")

        except Exception as e:
            logger.error(f"Error detecting faces: {e}", exc_info=True)

        return faces

    async def compare_faces(
        self, known_image_path: str, unknown_image_path: str, tolerance: float = 0.6
    ) -> List[Dict[str, Any]]:
        """Compare faces between two images.

        Args:
            known_image_path: Path to known face image
            unknown_image_path: Path to image with unknown faces
            tolerance: How much distance between faces to consider a match (lower = stricter)

        Returns:
            List of face matches with confidence scores
        """
        if not self.enabled:
            return []

        logger.info(f"Comparing faces: {known_image_path} vs {unknown_image_path}")
        matches = []

        try:
            import face_recognition

            # Load known image
            known_image = face_recognition.load_image_file(known_image_path)
            known_encodings = face_recognition.face_encodings(known_image)

            if not known_encodings:
                logger.warning("No faces found in known image")
                return []

            known_encoding = known_encodings[0]

            # Load unknown image
            unknown_image = face_recognition.load_image_file(unknown_image_path)
            unknown_face_locations = face_recognition.face_locations(unknown_image)
            unknown_encodings = face_recognition.face_encodings(
                unknown_image, unknown_face_locations
            )

            # Compare faces
            for idx, (location, encoding) in enumerate(
                zip(unknown_face_locations, unknown_encodings)
            ):
                # Calculate face distance (lower = more similar)
                face_distances = face_recognition.face_distance([known_encoding], encoding)
                distance = face_distances[0]

                is_match = distance <= tolerance
                confidence = 1.0 - distance  # Convert distance to confidence

                matches.append(
                    {
                        "face_id": idx,
                        "is_match": is_match,
                        "confidence": float(confidence),
                        "distance": float(distance),
                        "location": {
                            "top": location[0],
                            "right": location[1],
                            "bottom": location[2],
                            "left": location[3],
                        },
                    }
                )

            logger.info(
                f"Found {sum(1 for m in matches if m['is_match'])} matches out of {len(matches)} faces"
            )

        except Exception as e:
            logger.error(f"Error comparing faces: {e}", exc_info=True)

        return matches
