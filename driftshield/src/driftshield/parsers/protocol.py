"""Parser protocol for log ingestion."""

from typing import Protocol

from driftshield.core.models import CanonicalEvent


class TranscriptParser(Protocol):
    """Protocol for parsing agent transcripts into CanonicalEvents."""

    def parse(self, content: str) -> list[CanonicalEvent]:
        """Parse raw transcript content into canonical events."""
        ...

    def parse_file(self, file_path: str) -> list[CanonicalEvent]:
        """Parse transcript from file path."""
        ...

    @property
    def source_type(self) -> str:
        """Return identifier for this parser type (e.g., 'claude_code')."""
        ...

    @property
    def skipped_records_by_reason(self) -> dict[str, int] | None:
        """Source records the last parse() skipped, by reason; None if not counted."""
        ...

    @property
    def skipped_record_count(self) -> int | None:
        """Total records the last parse() skipped; None if the parser does not count."""
        ...


class NoSkipCountMixin:
    """For parsers that do not count skipped records: both counts are None."""

    @property
    def skipped_records_by_reason(self) -> dict[str, int] | None:
        return None

    @property
    def skipped_record_count(self) -> int | None:
        return None
