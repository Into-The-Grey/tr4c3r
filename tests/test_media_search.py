"""Tests for Image and Video OSINT module.

Tests reverse image search, EXIF extraction, video frame analysis,
and face recognition capabilities.
"""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from PIL import Image

from src.core.data_models import Result
from src.search.media import FaceRecognition, ImageSearch, VideoSearch


@pytest.fixture
def sample_image():
    """Create a sample test image."""
    img = Image.new("RGB", (100, 100), color="red")
    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        img.save(tmp.name)
        yield tmp.name
    Path(tmp.name).unlink(missing_ok=True)


@pytest.fixture
def sample_image_with_exif():
    """Create a sample image with EXIF data."""
    img = Image.new("RGB", (200, 200), color="blue")

    # Create EXIF data
    from PIL import Image as PILImage

    exif = img.getexif()
    exif[0x010F] = "TestCamera"  # Make
    exif[0x0110] = "TestModel"  # Model
    exif[0x0132] = "2025:01:01 12:00:00"  # DateTime

    with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
        img.save(tmp.name, exif=exif)
        yield tmp.name
    Path(tmp.name).unlink(missing_ok=True)


class TestImageSearch:
    """Test ImageSearch class."""

    @pytest.fixture
    def image_search(self):
        """Create ImageSearch instance."""
        return ImageSearch(config={"enabled_engines": ["google", "yandex"]})

    def test_initialization(self, image_search):
        """Test ImageSearch initialization."""
        assert image_search is not None
        assert "google" in image_search.enabled_engines
        assert "yandex" in image_search.enabled_engines

    def test_reverse_search_engines(self, image_search):
        """Test reverse search engine URLs are defined."""
        assert len(ImageSearch.REVERSE_SEARCH_ENGINES) >= 4
        assert "google" in ImageSearch.REVERSE_SEARCH_ENGINES
        assert "yandex" in ImageSearch.REVERSE_SEARCH_ENGINES
        assert "tineye" in ImageSearch.REVERSE_SEARCH_ENGINES
        assert "bing" in ImageSearch.REVERSE_SEARCH_ENGINES

    @pytest.mark.asyncio
    async def test_reverse_search(self, image_search):
        """Test reverse image search."""
        with patch.object(image_search.client, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response

            image_url = "https://example.com/test.jpg"
            results = await image_search.reverse_search(image_url)

            assert len(results) == 2  # google and yandex
            assert all(isinstance(r, Result) for r in results)
            assert all(r.identifier == image_url for r in results)
            assert all("reverse_image" in r.source for r in results)

    @pytest.mark.asyncio
    async def test_reverse_search_invalid_url(self, image_search):
        """Test reverse search with invalid URL."""
        with patch.object(image_search.client, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.status_code = 404
            mock_get.return_value = mock_response

            results = await image_search.reverse_search("https://invalid.com/nonexistent.jpg")
            assert len(results) == 0

    @pytest.mark.asyncio
    async def test_extract_metadata_from_file(self, image_search, sample_image):
        """Test metadata extraction from local file."""
        metadata = await image_search.extract_metadata(sample_image)

        assert metadata["format"] == "JPEG"
        assert "size" in metadata
        assert metadata["size"]["width"] == 100
        assert metadata["size"]["height"] == 100
        assert "hashes" in metadata
        assert "md5" in metadata["hashes"]
        assert "sha256" in metadata["hashes"]

    @pytest.mark.asyncio
    async def test_extract_metadata_with_exif(self, image_search, sample_image_with_exif):
        """Test EXIF data extraction."""
        metadata = await image_search.extract_metadata(sample_image_with_exif)

        assert "exif" in metadata
        # EXIF data should contain camera info
        assert metadata["size"]["width"] == 200

    @pytest.mark.asyncio
    async def test_extract_metadata_from_url(self, image_search, sample_image):
        """Test metadata extraction from URL."""
        with open(sample_image, "rb") as f:
            image_data = f.read()

        with patch.object(image_search.client, "get") as mock_get:
            mock_response = MagicMock()
            mock_response.content = image_data
            mock_get.return_value = mock_response

            metadata = await image_search.extract_metadata("https://example.com/test.jpg")
            assert metadata["format"] == "JPEG"

    @pytest.mark.asyncio
    async def test_search_by_hash(self, image_search, sample_image):
        """Test image hash search."""
        results = await image_search.search_by_hash(sample_image)

        assert len(results) == 2  # md5 and sha256
        assert all(isinstance(r, Result) for r in results)
        assert any("md5" in r.source for r in results)
        assert any("sha256" in r.source for r in results)

    def test_convert_to_degrees(self, image_search):
        """Test GPS coordinate conversion."""
        # 40°26'46"N = 40.446111
        degrees = image_search._convert_to_degrees((40, 26, 46))
        assert abs(degrees - 40.446111) < 0.0001

    def test_parse_gps_with_coordinates(self, image_search):
        """Test GPS parsing with coordinates."""
        gps_info = {
            "GPSLatitude": (40, 26, 46),
            "GPSLatitudeRef": "N",
            "GPSLongitude": (79, 58, 56),
            "GPSLongitudeRef": "W",
        }

        gps_data = image_search._parse_gps(gps_info)

        assert "coordinates" in gps_data
        assert abs(gps_data["coordinates"]["latitude"] - 40.446111) < 0.0001
        assert abs(gps_data["coordinates"]["longitude"] - (-79.982222)) < 0.0001

    @pytest.mark.asyncio
    async def test_extract_metadata_error_handling(self, image_search):
        """Test error handling in metadata extraction."""
        metadata = await image_search.extract_metadata("/nonexistent/file.jpg")
        assert "error" in metadata


class TestVideoSearch:
    """Test VideoSearch class."""

    @pytest.fixture
    def video_search(self):
        """Create VideoSearch instance."""
        return VideoSearch(config={})

    def test_initialization(self, video_search):
        """Test VideoSearch initialization."""
        assert video_search is not None

    @pytest.mark.asyncio
    async def test_extract_frames_no_opencv(self, video_search):
        """Test frame extraction without OpenCV."""
        with patch.dict("sys.modules", {"cv2": None}):
            frames = await video_search.extract_frames("test.mp4")
            assert len(frames) == 0

    @pytest.mark.asyncio
    async def test_analyze_video_metadata_no_opencv(self, video_search):
        """Test video metadata analysis without OpenCV."""
        # Skip cv2 import by catching the ImportError
        with patch.dict("sys.modules", {"cv2": None}):
            metadata = await video_search.analyze_video_metadata("test.mp4")
            assert "extracted_at" in metadata

    @pytest.mark.asyncio
    async def test_analyze_video_metadata_with_mock(self, video_search):
        """Test video metadata with mocked OpenCV."""
        # Mock cv2 module
        mock_cv2 = MagicMock()
        mock_cap = MagicMock()
        mock_cap.isOpened.return_value = True
        mock_cap.get.side_effect = lambda prop: {
            7: 100,  # FRAME_COUNT
            5: 30.0,  # FPS
            3: 1920,  # WIDTH
            4: 1080,  # HEIGHT
        }.get(prop, 0)

        mock_cv2.VideoCapture.return_value = mock_cap
        mock_cv2.CAP_PROP_FRAME_COUNT = 7
        mock_cv2.CAP_PROP_FPS = 5
        mock_cv2.CAP_PROP_FRAME_WIDTH = 3
        mock_cv2.CAP_PROP_FRAME_HEIGHT = 4

        # Create temp file
        with tempfile.NamedTemporaryFile(suffix=".mp4", delete=False) as tmp:
            tmp.write(b"fake video data")
            video_path = tmp.name

        try:
            with patch.dict("sys.modules", {"cv2": mock_cv2}):
                # Need to reimport to get mocked cv2
                import sys

                if "cv2" in sys.modules:
                    del sys.modules["cv2"]

                metadata = await video_search.analyze_video_metadata(video_path)

                # Will have file_size_bytes at minimum
                assert "file_size_bytes" in metadata
                assert metadata["file_size_bytes"] > 0
        finally:
            Path(video_path).unlink(missing_ok=True)


class TestFaceRecognition:
    """Test FaceRecognition class."""

    @pytest.fixture
    def face_recognition_module(self):
        """Create FaceRecognition instance."""
        return FaceRecognition()

    def test_initialization(self, face_recognition_module):
        """Test FaceRecognition initialization."""
        assert face_recognition_module is not None

    def test_check_dependencies(self, face_recognition_module):
        """Test dependency checking."""
        # Will be True or False depending on if face_recognition is installed
        assert isinstance(face_recognition_module.enabled, bool)

    @pytest.mark.asyncio
    async def test_detect_faces_not_enabled(self, face_recognition_module):
        """Test face detection when library not available."""
        with patch.object(face_recognition_module, "enabled", False):
            faces = await face_recognition_module.detect_faces("test.jpg")
            assert len(faces) == 0

    @pytest.mark.asyncio
    async def test_compare_faces_not_enabled(self, face_recognition_module):
        """Test face comparison when library not available."""
        with patch.object(face_recognition_module, "enabled", False):
            matches = await face_recognition_module.compare_faces("face1.jpg", "face2.jpg")
            assert len(matches) == 0

    @pytest.mark.asyncio
    async def test_detect_faces_with_mock(self, face_recognition_module, sample_image):
        """Test face detection with mocked library."""
        # Mock face_recognition as a module in sys.modules
        mock_fr = MagicMock()
        mock_fr.load_image_file.return_value = MagicMock()
        mock_fr.face_locations.return_value = [(10, 90, 90, 10)]  # top, right, bottom, left

        # Create mock encoding object with tolist() method
        mock_encoding = MagicMock()
        mock_encoding.tolist.return_value = [0.1] * 128
        mock_fr.face_encodings.return_value = [mock_encoding]

        with patch.dict("sys.modules", {"face_recognition": mock_fr}):
            # Manually enable since the mock is now available
            face_recognition_module.enabled = True

            faces = await face_recognition_module.detect_faces(sample_image)

            assert len(faces) == 1
            assert faces[0]["face_id"] == 0
            assert "location" in faces[0]
            assert "encoding" in faces[0]
            assert faces[0]["location"]["top"] == 10

    @pytest.mark.asyncio
    async def test_compare_faces_with_mock(self, face_recognition_module, sample_image):
        """Test face comparison with mocked library."""
        # Mock face_recognition module
        mock_fr = MagicMock()
        mock_fr.load_image_file.return_value = MagicMock()
        mock_fr.face_encodings.side_effect = [
            [[0.1] * 128],  # Known face
            [[0.1] * 128, [0.9] * 128],  # Unknown faces
        ]
        mock_fr.face_locations.return_value = [
            (10, 90, 90, 10),
            (100, 190, 190, 100),
        ]
        mock_fr.face_distance.side_effect = [
            [0.3],  # First face - close match
            [0.8],  # Second face - no match
        ]

        with patch.dict("sys.modules", {"face_recognition": mock_fr}):
            face_recognition_module.enabled = True

            matches = await face_recognition_module.compare_faces(sample_image, sample_image)

            assert len(matches) == 2
            assert matches[0]["is_match"] is True
            assert matches[0]["confidence"] > 0.6
            assert matches[1]["is_match"] is False


class TestImageMetadata:
    """Test image metadata extraction edge cases."""

    @pytest.fixture
    def image_search(self):
        return ImageSearch()

    @pytest.mark.asyncio
    async def test_metadata_with_various_formats(self, image_search):
        """Test metadata extraction with different image formats."""
        formats = ["PNG", "BMP", "GIF"]

        for fmt in formats:
            img = Image.new("RGB", (50, 50), color="green")
            with tempfile.NamedTemporaryFile(suffix=f".{fmt.lower()}", delete=False) as tmp:
                img.save(tmp.name, format=fmt)

                try:
                    metadata = await image_search.extract_metadata(tmp.name)
                    assert metadata["format"] in [fmt, fmt.upper()]
                    assert "size" in metadata
                finally:
                    Path(tmp.name).unlink(missing_ok=True)

    @pytest.mark.asyncio
    async def test_metadata_file_hashes(self, image_search, sample_image):
        """Test that image hashes are consistent."""
        metadata1 = await image_search.extract_metadata(sample_image)
        metadata2 = await image_search.extract_metadata(sample_image)

        assert metadata1["hashes"]["md5"] == metadata2["hashes"]["md5"]
        assert metadata1["hashes"]["sha256"] == metadata2["hashes"]["sha256"]


class TestReverseSearchURLs:
    """Test reverse search URL generation."""

    def test_google_search_url(self):
        """Test Google reverse search URL format."""
        image_url = "https://example.com/image.jpg"
        search_url = ImageSearch.REVERSE_SEARCH_ENGINES["google"].format(
            url=image_url.replace("://", "%3A%2F%2F")
        )
        assert "google.com/searchbyimage" in search_url

    def test_yandex_search_url(self):
        """Test Yandex reverse search URL format."""
        search_url = ImageSearch.REVERSE_SEARCH_ENGINES["yandex"]
        assert "yandex.com" in search_url
        assert "imageview" in search_url

    def test_tineye_search_url(self):
        """Test TinEye reverse search URL format."""
        search_url = ImageSearch.REVERSE_SEARCH_ENGINES["tineye"]
        assert "tineye.com" in search_url

    def test_bing_search_url(self):
        """Test Bing reverse search URL format."""
        search_url = ImageSearch.REVERSE_SEARCH_ENGINES["bing"]
        assert "bing.com" in search_url
