import cv2
import numpy as np
from PIL import Image


def extract_qr_data(image_path):
    try:
        image = cv2.imread(image_path)

        detector = cv2.QRCodeDetector()

        data, bbox, _ = detector.detectAndDecode(image)

        if data:
            return {
                "success": True,
                "data": data
            }

        return {
            "success": False,
            "message": "No QR code found"
        }

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }