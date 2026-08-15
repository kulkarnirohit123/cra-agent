"""Diff analyzer — extracts structured file changes from git commits.

Parses git diffs into structured FileChange objects with hunks,
providing context for vulnerability scanners.
"""

from __future__ import annotations

import re
from pathlib import Path

import git
from git import Repo

from src.core.models import ChangeType, FileChange, Hunk
from src.utils.logger import get_logger

logger = get_logger(__name__)


# Language detection based on file extension
EXTENSION_TO_LANGUAGE: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".jsx": "javascript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rs": "rust",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sh": "shell",
    ".bash": "shell",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".json": "json",
    ".xml": "xml",
    ".html": "html",
    ".css": "css",
    ".scss": "scss",
    ".sql": "sql",
}


class DiffAnalyzer:
    """Analyzes git diffs and produces structured FileChange objects."""

    def __init__(self, repo_path: Path) -> None:
        """Initialize the diff analyzer.

        Args:
            repo_path: Path to the git repository.
        """
        self.repo_path = repo_path
        self._repo: Repo | None = None

    @property
    def repo(self) -> Repo:
        """Get or initialize the git repository."""
        if self._repo is None:
            self._repo = Repo(self.repo_path)
        return self._repo

    def analyze_commit(self, commit_hash: str) -> list[FileChange]:
        """Analyze a commit and return structured file changes.

        Args:
            commit_hash: The commit hash to analyze.

        Returns:
            List of FileChange objects representing the changes.
        """
        try:
            commit = self.repo.commit(commit_hash)

            if commit.parents:
                parent = commit.parents[0]
                diffs = commit.diff(parent, create_patch=True)
            else:
                # Initial commit - diff against empty tree
                diffs = commit.diff(git.NULL_TREE, create_patch=True)

            file_changes: list[FileChange] = []

            for diff in diffs:
                file_change = self._parse_diff(diff, commit_hash)
                if file_change:
                    file_changes.append(file_change)

            logger.info(
                "Analyzed commit",
                commit=commit_hash[:7],
                files_changed=len(file_changes),
            )
            return file_changes

        except Exception as e:
            logger.error("Error analyzing commit", commit=commit_hash[:7], error=str(e))
            return []

    def _parse_diff(self, diff: git.Diff, commit_hash: str) -> FileChange | None:
        """Parse a single git diff into a FileChange object.

        Args:
            diff: The git diff object.
            commit_hash: The commit hash for context.

        Returns:
            FileChange object or None if parsing fails.
        """
        try:
            # Determine change type
            if diff.new_file:
                change_type = ChangeType.ADDED
            elif diff.deleted_file:
                change_type = ChangeType.DELETED
            elif diff.renamed_file:
                change_type = ChangeType.RENAMED
            else:
                change_type = ChangeType.MODIFIED

            # Get file path
            file_path = diff.b_path or diff.a_path or ""
            old_path = diff.a_path if diff.renamed_file else None

            # Parse hunks from the diff
            hunks = self._parse_hunks(diff.diff.decode("utf-8", errors="replace"))

            # Detect language
            file_extension = Path(file_path).suffix.lower()
            language = EXTENSION_TO_LANGUAGE.get(file_extension, "")

            # Get file content (for new/modified files)
            file_content = None
            if change_type in (ChangeType.ADDED, ChangeType.MODIFIED):
                try:
                    blob = self.repo.commit(commit_hash).tree / file_path
                    file_content = blob.data_stream.read().decode("utf-8", errors="replace")
                except (KeyError, TypeError):
                    pass

            return FileChange(
                file_path=file_path,
                change_type=change_type,
                old_path=old_path,
                hunks=hunks,
                file_content=file_content,
                file_extension=file_extension,
                language=language,
            )

        except Exception as e:
            logger.warning("Error parsing diff", error=str(e))
            return None

    def _parse_hunks(self, diff_text: str) -> list[Hunk]:
        """Parse unified diff text into Hunk objects.

        Args:
            diff_text: The unified diff text.

        Returns:
            List of Hunk objects.
        """
        hunks: list[Hunk] = []

        # Match hunk headers: @@ -old_start,old_count +new_start,new_count @@
        hunk_pattern = re.compile(
            r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@",
            re.MULTILINE,
        )

        matches = list(hunk_pattern.finditer(diff_text))

        for i, match in enumerate(matches):
            old_start = int(match.group(1))
            old_count = int(match.group(2)) if match.group(2) else 1
            new_start = int(match.group(3))
            new_count = int(match.group(4)) if match.group(4) else 1

            # Get the hunk content (lines between this header and the next)
            start_pos = match.end()
            end_pos = matches[i + 1].start() if i + 1 < len(matches) else len(diff_text)
            hunk_content = diff_text[start_pos:end_pos]

            # Parse lines
            added_lines: list[str] = []
            removed_lines: list[str] = []
            context_lines: list[str] = []

            for line in hunk_content.split("\n"):
                if line.startswith("+"):
                    added_lines.append(line[1:])
                elif line.startswith("-"):
                    removed_lines.append(line[1:])
                elif line.startswith(" "):
                    context_lines.append(line[1:])

            hunks.append(
                Hunk(
                    old_start=old_start,
                    old_count=old_count,
                    new_start=new_start,
                    new_count=new_count,
                    added_lines=added_lines,
                    removed_lines=removed_lines,
                    context_lines=context_lines,
                )
            )

        return hunks

    def get_file_content_at_commit(self, file_path: str, commit_hash: str) -> str | None:
        """Get the content of a file at a specific commit.

        Args:
            file_path: Path to the file.
            commit_hash: The commit hash.

        Returns:
            File content as string, or None if not found.
        """
        try:
            blob = self.repo.commit(commit_hash).tree / file_path
            return blob.data_stream.read().decode("utf-8", errors="replace")
        except (KeyError, TypeError):
            return None

    def get_surrounding_context(
        self,
        file_path: str,
        commit_hash: str,
        line_number: int,
        context_lines: int = 10,
    ) -> str:
        """Get surrounding context for a specific line in a file.

        Args:
            file_path: Path to the file.
            commit_hash: The commit hash.
            line_number: The line number to get context for.
            context_lines: Number of lines before and after to include.

        Returns:
            Context string with line numbers.
        """
        content = self.get_file_content_at_commit(file_path, commit_hash)
        if not content:
            return ""

        lines = content.split("\n")
        start = max(0, line_number - context_lines - 1)
        end = min(len(lines), line_number + context_lines)

        context_parts = []
        for i in range(start, end):
            marker = ">>>" if i == line_number - 1 else "   "
            context_parts.append(f"{marker} {i + 1:4d} | {lines[i]}")

        return "\n".join(context_parts)
