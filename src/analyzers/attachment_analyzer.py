import os


class AttachmentAnalyzer:

    EXECUTABLE_EXTENSIONS = {
        ".exe", ".msi", ".bat", ".cmd", ".scr", ".com"
    }

    SCRIPT_EXTENSIONS = {
        ".js", ".jse", ".vbs", ".vbe",
        ".ps1", ".psm1", ".hta"
    }

    MACRO_EXTENSIONS = {
        ".docm", ".xlsm", ".pptm"
    }

    ARCHIVE_EXTENSIONS = {
        ".zip", ".rar", ".7z", ".iso"
    }

    def analyze(self, attachments):

        score = 0
        evidence = []

        for attachment in attachments:

            filename = attachment.get("filename", "")
            size = attachment.get("size", 0)

            _, extension = os.path.splitext(
                filename.lower()
            )

            if extension in self.EXECUTABLE_EXTENSIONS:
                score += 40
                evidence.append(
                    f"Executable attachment: {filename}"
                )

            if extension in self.SCRIPT_EXTENSIONS:
                score += 35
                evidence.append(
                    f"Script attachment: {filename}"
                )

            if extension in self.MACRO_EXTENSIONS:
                score += 30
                evidence.append(
                    f"Macro-enabled Office document: {filename}"
                )

            if extension in self.ARCHIVE_EXTENSIONS:
                score += 15
                evidence.append(
                    f"Archive attachment: {filename}"
                )

            if filename.count(".") >= 2:
                score += 15
                evidence.append(
                    f"Multiple extensions: {filename}"
                )

            if size > 10 * 1024 * 1024:
                score += 5
                evidence.append(
                    f"Large attachment: {filename}"
                )

        return {
            "attachment_count": len(attachments),
            "risk_score": min(score, 100),
            "evidence": evidence
        }