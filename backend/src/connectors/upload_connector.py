import os
import uuid

from fastapi import UploadFile, HTTPException

from src.connectors.base_connector import BaseConnector


class UploadConnector(BaseConnector):

    def __init__(self):

        self.upload_dir = "uploads"

        os.makedirs(
            self.upload_dir,
            exist_ok=True
        )

    async def get_email(self, file: UploadFile):

        if not file.filename.lower().endswith(".eml"):

            raise HTTPException(
                status_code=400,
                detail="Only .eml files are supported"
            )

        file_id = str(uuid.uuid4())

        file_path = os.path.join(
            self.upload_dir,
            f"{file_id}.eml"
        )

        content = await file.read()

        with open(file_path, "wb") as buffer:
            buffer.write(content)

        return {
            "id": file_id,
            "filename": file.filename,
            "path": file_path
        }