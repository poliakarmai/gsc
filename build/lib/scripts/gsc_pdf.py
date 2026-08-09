#!/usr/bin/env python3
"""GSC PDF Export — generates PDF report from findings."""
import sys, os

def export_pdf(project: str = None, output: str = None):
    """Export findings as PDF. Requires weasyprint."""
    try:
        from weasyprint import HTML
    except ImportError:
        print("Install weasyprint: pip install weasyprint")
        return

    # Generate HTML first (reuse gsc_report.py)
    html_path = "/tmp/gsc_report_temp.html"
    os.system(f"python3 {os.path.dirname(__file__)}/gsc_report.py {project or ''} {html_path}")

    out = output or f"/tmp/gsc_report_{project or 'all'}.pdf"
    HTML(filename=html_path).write_pdf(out)
    print(f"✅ PDF: {out}")

if __name__ == "__main__":
    project = sys.argv[1] if len(sys.argv) > 1 else None
    output = sys.argv[2] if len(sys.argv) > 2 else None
    export_pdf(project, output)
