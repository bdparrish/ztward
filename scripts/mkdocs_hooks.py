"""MkDocs hook: point links to files outside the published docs at GitHub.

The docs link to source code, config examples and repository files (e.g.
`../go/pkg/validators/ztdf.go`) that are not part of the site. On GitHub those
relative links work; on the site they would 404. This rewrites them, and links
to docs excluded from the site, to their GitHub URL. Fenced code blocks are
left untouched.
"""

import os
import re

GITHUB = "https://github.com/bdparrish/ztward"
BRANCH = "main"

# [text](target) and ![alt](target), with an optional "title".
LINK = re.compile(r'(!?\[[^\]]*\]\()([^)\s]+)((?:\s+"[^"]*")?\))')
FENCE = re.compile(r"^(```|~~~)", re.M)


def on_page_markdown(markdown, page, config, files):
    repo_root = os.path.dirname(config["config_file_path"])
    docs_dir = os.path.relpath(config["docs_dir"], repo_root)
    published = {f.src_uri for f in files}
    page_dir = os.path.dirname(page.file.src_uri)

    def rewrite(match):
        prefix, target, suffix = match.groups()
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith(("#", "/")):
            return match.group(0)  # absolute URL, mailto:, in-page anchor
        path, _, anchor = target.partition("#")
        in_docs = os.path.normpath(os.path.join(page_dir, path))
        if not in_docs.startswith("..") and in_docs in published:
            return match.group(0)  # a page or asset that is on the site
        repo_path = os.path.normpath(os.path.join(docs_dir, page_dir, path))
        kind = "tree" if os.path.isdir(os.path.join(repo_root, repo_path)) else "blob"
        url = f"{GITHUB}/{kind}/{BRANCH}/{repo_path}" + (f"#{anchor}" if anchor else "")
        return prefix + url + suffix

    # Only rewrite outside fenced code blocks: each fence marker toggles in/out.
    parts = FENCE.split(markdown)
    out, inside = [], False
    for part in parts:
        if part in ("```", "~~~"):
            inside = not inside
            out.append(part)
        else:
            out.append(part if inside else LINK.sub(rewrite, part))
    return "".join(out)
