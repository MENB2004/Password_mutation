import sys
import runpy
from pathlib import Path

# Ensure package is on sys.path
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))


def is_running_under_streamlit() -> bool:
    """Detect if executed inside Streamlit runtime (e.g. Streamlit Cloud)."""
    if "streamlit" not in sys.modules:
        return False
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        return get_script_run_ctx() is not None
    except Exception:
        return True


def main():
    if is_running_under_streamlit():
        # Delegating to Streamlit web application
        app_file = ROOT_DIR / "app.py"
        runpy.run_path(str(app_file), run_name="__main__")
        return

    from password_analyzer.cli import main as cli_main
    cli_main()


if __name__ == "__main__":
    main()

