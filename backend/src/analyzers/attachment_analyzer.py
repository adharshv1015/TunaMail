import os


class AttachmentAnalyzer:

    EXECUTABLE_EXTENSIONS = {
        ".exe",
        ".msi",
        ".bat",
        ".cmd",
        ".scr",
        ".com"
    }

    SCRIPT_EXTENSIONS = {
        ".js",
        ".jse",
        ".vbs",
        ".vbe",
        ".ps1",
        ".psm1",
        ".hta"
    }

    MACRO_EXTENSIONS = {
        ".docm",
        ".xlsm",
        ".pptm"
    }

    ARCHIVE_EXTENSIONS = {
        ".zip",
        ".rar",
        ".7z",
        ".iso"
    }

    DOUBLE_EXTENSION_RISK = 15
    LARGE_FILE_RISK = 5

    def analyze(self, attachments):

        score = 0
        evidence = []

        for attachment in attachments:

            filename = attachment.get("filename") or ""
            filename = filename.strip()
            size = attachment.get("size", 0) or 0

            if not filename:
                continue

            filename_lower = filename.lower()

            _, extension = os.path.splitext(
                filename_lower
            )

            # ---------------------------------
            # Executable
            # ---------------------------------
            if extension in self.EXECUTABLE_EXTENSIONS:

                score += 40

                evidence.append(
                    f"Executable attachment: {filename}"
                )

            # ---------------------------------
            # Script
            # ---------------------------------
            if extension in self.SCRIPT_EXTENSIONS:

                score += 35

                evidence.append(
                    f"Script attachment: {filename}"
                )

            # ---------------------------------
            # Macro-enabled Office document
            # ---------------------------------
            if extension in self.MACRO_EXTENSIONS:

                score += 30

                evidence.append(
                    f"Macro-enabled Office document: {filename}"
                )

            # ---------------------------------
            # Archive
            # ---------------------------------
            if extension in self.ARCHIVE_EXTENSIONS:

                score += 15

                evidence.append(
                    f"Archive attachment: {filename}"
                )

            # ---------------------------------
            # Multiple extensions
            # Example:
            # invoice.pdf.exe
            # document.docx.js
            # ---------------------------------
            if filename.count(".") >= 2:

                score += self.DOUBLE_EXTENSION_RISK

                evidence.append(
                    f"Multiple extensions: {filename}"
                )

            # ---------------------------------
            # Large attachment
            # ---------------------------------
            if size > 10 * 1024 * 1024:

                score += self.LARGE_FILE_RISK

                evidence.append(
                    f"Large attachment: {filename}"
                )

        return {
            "attachment_count": len(attachments),
            "risk_score": min(score, 100),
            "evidence": evidence
        }