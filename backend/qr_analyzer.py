from pyzbar.pyzbar import decode
from PIL import Image


def extract_qr_data(image: Image.Image):
    decoded_objects = decode(image)

    results = []

    for obj in decoded_objects:
        data = obj.data.decode("utf-8")
        results.append(data)

    return results
