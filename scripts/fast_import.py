"""Generated files written as git fast-import file changes, so that they can be
committed without being written to disk one by one and read back by git.

The output is only the file changes of a commit command. The command itself,
and the stream around it, are left to whoever runs fast-import.
"""

from pathlib import Path


class FastImportFiles:
    def __init__(self, path: Path):
        self._file = path.open('wb')

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self._file.close()

    def write(self, path: str, content: str):
        # A path which fast-import would need quoted isn't supported.
        if path.startswith('"') or '\n' in path:
            raise Exception(f'Unsupported path: {path}')

        data = content.encode()
        self._file.write(b'M 100644 inline %b\ndata %d\n%b\n' % (path.encode(), len(data), data))
