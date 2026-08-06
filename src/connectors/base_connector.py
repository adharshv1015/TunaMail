from abc import ABC, abstractmethod


class BaseConnector(ABC):

    @abstractmethod
    async def get_email(self, *args, **kwargs):
        """
        Return email metadata needed by EmailAnalyzer.

        Every connector (Upload, Gmail, Outlook, IMAP)
        must implement this method.
        """
        pass