
import re, unicodedata

_FENCES = re.compile(r"```(?:\w+)?\s*\n([\s\S]*?)\n```", re.MULTILINE)

def extract_java_source(text: str) -> str:
    # If fenced blocks exist, take the largest block (or the one the model fenced)
    blocks = _FENCES.findall(text)
    code = max(blocks, key=len) if blocks else text

    # Strip any stray starting/ending fences that survived, or <code> tags
    code = re.sub(r"^\s*```+\s*|\s*```+\s*$", "", code.strip())
    code = re.sub(r"</?code>", "", code, flags=re.I)

    # Remove invisible formatting chars that can break javac (e.g., zero-width joiners)
    code = "".join(ch for ch in code if unicodedata.category(ch) != "Cf")

    # Normalize newlines + ensure trailing newline
    return code.replace("\r\n", "\n").replace("\r", "\n").strip() + "\n"
