"""hunt command."""


def run(target: str, vuln_class: str = None, resume: bool = False) -> None:
    print(f"Hunt: {target} vuln_class={vuln_class} resume={resume}")
    print("Note: Load an engagement first with 'shadow new'")
