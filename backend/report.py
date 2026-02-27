class ReportBuilder:
    """Accumulates markdown sections into a penetration test report."""

    def __init__(self, target: str):
        self.sections: list[str] = [
            f"# Penetration Test Report: {target}\n",
        ]

    def append(self, markdown: str):
        """Append a section to the report."""
        self.sections.append(markdown)

    def get_markdown(self) -> str:
        """Return the full report as markdown."""
        return '\n\n'.join(self.sections)
