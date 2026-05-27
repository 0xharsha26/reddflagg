import cv2
import numpy as np
from PIL import Image

def extract_qr_data(image_input):
    """
    Extracts QR data from a PIL Image, file path string, or numpy array.
    Uses pyzbar first and falls back to OpenCV's QRCodeDetector.
    """
    try:
        # 1. Convert various input types to PIL Image and OpenCV BGR format
        if isinstance(image_input, str):
            image = cv2.imread(image_input)
            pil_image = Image.open(image_input)
        elif isinstance(image_input, Image.Image):
            pil_image = image_input
            # Convert PIL to numpy (OpenCV BGR)
            image = np.array(pil_image)
            if len(image.shape) == 3:
                if image.shape[2] == 4:
                    image = cv2.cvtColor(image, cv2.COLOR_RGBA2BGR)
                else:
                    image = cv2.cvtColor(image, cv2.COLOR_RGB2BGR)
        elif isinstance(image_input, np.ndarray):
            image = image_input
            pil_image = Image.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
        else:
            return {
                "success": False,
                "message": "Unsupported image format provided."
            }

        # 2. Try pyzbar first
        try:
            from pyzbar.pyzbar import decode
            decoded_objects = decode(pil_image)
            if decoded_objects:
                qr_text = decoded_objects[0].data.decode('utf-8')
                return {
                    "success": True,
                    "data": qr_text
                }
        except Exception as zbar_err:
            # Silently log if libzbar is not installed on system and try OpenCV
            print(f"pyzbar decoding skipped/failed: {zbar_err}")

        # 3. Try OpenCV QRCodeDetector fallback
        if image is not None:
            detector = cv2.QRCodeDetector()
            data, bbox, _ = detector.detectAndDecode(image)
            if data:
                return {
                    "success": True,
                    "data": data
                }

        return {
            "success": False,
            "message": "No QR code detected in the uploaded image."
        }

    except Exception as e:
        return {
            "success": False,
            "message": f"Failed to extract QR code data: {str(e)}"
        }