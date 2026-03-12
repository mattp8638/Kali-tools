"""
Report Engine
Generates pentest reports from aggregated tool findings.
Outputs: HTML (self-contained, offline), JSON, TXT, PDF (reportlab).
Fully Windows-compatible — no external binaries required.
"""
import datetime
import json
import os
import sys
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False


SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

SEV_COLOURS = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f1c40f",
    "LOW":      "#27ae60",
    "INFO":     "#2980b9",
}

SEV_BG = {
    "CRITICAL": "#fdecea",
    "HIGH":     "#fef5ec",
    "MEDIUM":   "#fefce8",
    "LOW":      "#eafaf1",
    "INFO":     "#eaf4fb",
}


def generate(
    findings: List[Dict],
    output_format: str,
    output_path: str,
    title: str = "Pentest Report",
    target: str = "",
    operator: str = "",
    severity_filter: str = "all",
    auto_open: bool = True,
    on_output=None,
) -> Dict[str, Any]:
    """
    Generate a report from a list of findings.

    Each finding dict should contain:
        severity, title, target, tool, detail
    """
    findings = _filter_findings(findings, severity_filter)
    findings = _sort_findings(findings)
    counts   = _count_severities(findings)
    meta = {
        "title":    title,
        "target":   target,
        "operator": operator,
        "date":     datetime.datetime.now().strftime("%Y-%m-%d %H:%M"),
        "counts":   counts,
        "total":    len(findings),
        "risk":     _risk_rating(counts),
    }

    fmt = output_format.strip().lower()
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    if fmt == "html":
        _write_html(findings, meta, output_path)
    elif fmt == "json":
        _write_json(findings, meta, output_path)
    elif fmt == "txt":
        _write_txt(findings, meta, output_path)
    elif fmt == "pdf":
        if REPORTLAB_OK:
            _write_pdf(findings, meta, output_path)
        else:
            html_path = output_path.replace(".pdf", ".html")
            _write_html(findings, meta, html_path)
            output_path = html_path
            _emit(on_output,
                  "[!] reportlab not installed — generated HTML instead. "
                  "pip install reportlab for PDF.")
    else:
        return {"status": f"Unknown format: {fmt}", "path": ""}

    _emit(on_output, f"[+] Report written: {output_path}")

    if auto_open and os.path.exists(output_path):
        try:
            os.startfile(output_path)   # Windows
        except AttributeError:
            import subprocess
            subprocess.Popen(["xdg-open", output_path])  # Linux fallback

    return {"status": "ok", "path": output_path, "meta": meta}


# ============================================================================
# HTML
# ============================================================================

def _write_html(findings: List[Dict], meta: Dict, path: str):
    counts = meta["counts"]
    risk   = meta["risk"]
    risk_col = SEV_COLOURS.get(risk, "#555")

    badge_html = "".join(
        f'<span class="badge" style="background:{SEV_COLOURS[s]}">'
        f'{s} <strong>{counts.get(s, 0)}</strong></span>'
        for s in SEV_ORDER if counts.get(s, 0) > 0
    )

    rows_html = ""
    for i, f in enumerate(findings):
        sev  = f.get("severity", "INFO")
        col  = SEV_COLOURS.get(sev, "#555")
        bg   = SEV_BG.get(sev, "#fff")
        rows_html += (
            f'<tr style="background:{bg}">'
            f'<td>{i+1}</td>'
            f'<td><span class="sev-pill" style="background:{col}">{sev}</span></td>'
            f'<td>{_he(f.get("title", ""))}</td>'
            f'<td><code>{_he(f.get("target", ""))}</code></td>'
            f'<td>{_he(f.get("tool", ""))}</td>'
            f'<td class="detail">{_he(str(f.get("detail", "")))}</td>'
            f'</tr>\n'
        )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_he(meta['title'])}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',Arial,sans-serif;background:#f4f6f9;color:#222;font-size:14px}}
  .wrap{{max-width:1200px;margin:0 auto;padding:32px 24px}}
  .cover{{background:linear-gradient(135deg,#1a1a2e 0%,#16213e 60%,#0f3460 100%);
    color:#fff;padding:60px 48px;border-radius:12px;margin-bottom:32px}}
  .cover h1{{font-size:2.4em;letter-spacing:1px;margin-bottom:8px}}
  .cover .sub{{font-size:1em;opacity:.75;margin-bottom:32px}}
  .cover-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:24px}}
  .cover-item{{background:rgba(255,255,255,.08);border-radius:8px;padding:16px}}
  .cover-item label{{font-size:.75em;opacity:.6;text-transform:uppercase;letter-spacing:1px}}
  .cover-item .val{{font-size:1.1em;font-weight:600;margin-top:4px}}
  .risk-badge{{display:inline-block;padding:6px 18px;border-radius:20px;
    font-weight:700;font-size:1em;background:{risk_col};color:#fff;margin-top:12px}}
  .summary{{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:32px}}
  .badge{{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;
    border-radius:8px;color:#fff;font-size:.95em;font-weight:500}}
  .badge strong{{font-size:1.3em}}
  h2{{font-size:1.3em;color:#1a1a2e;border-bottom:2px solid #1a1a2e;
    padding-bottom:6px;margin:32px 0 16px}}
  table{{width:100%;border-collapse:collapse;background:#fff;
    border-radius:8px;overflow:hidden;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
  th{{background:#1a1a2e;color:#fff;padding:10px 14px;text-align:left;font-size:.85em}}
  td{{padding:10px 14px;border-bottom:1px solid #eee;vertical-align:top}}
  tr:last-child td{{border-bottom:none}}
  .sev-pill{{display:inline-block;padding:3px 10px;border-radius:12px;
    color:#fff;font-size:.8em;font-weight:700;white-space:nowrap}}
  .detail{{font-size:.82em;color:#555;max-width:300px;word-break:break-all}}
  code{{background:#f0f0f0;padding:2px 6px;border-radius:4px;font-size:.85em}}
  .footer{{text-align:center;margin-top:48px;font-size:.8em;color:#999}}
  @media print{{
    body{{background:#fff}}
    .wrap{{max-width:100%;padding:16px}}
    .cover{{break-after:page}}
  }}
</style>
</head>
<body>
<div class="wrap">
  <div class="cover">
    <div class="sub">PENETRATION TEST REPORT</div>
    <h1>{_he(meta['title'])}</h1>
    <div class="risk-badge">Overall Risk: {risk}</div>
    <div class="cover-grid">
      <div class="cover-item"><label>Target</label>
        <div class="val">{_he(meta['target'] or 'N/A')}</div></div>
      <div class="cover-item"><label>Operator</label>
        <div class="val">{_he(meta['operator'] or 'N/A')}</div></div>
      <div class="cover-item"><label>Date</label>
        <div class="val">{meta['date']}</div></div>
    </div>
  </div>
  <h2>Executive Summary</h2>
  <p style="margin-bottom:16px;line-height:1.7">
    This report summarises the findings from an automated penetration test
    against <strong>{_he(meta['target'] or 'the target')}</strong>.
    A total of <strong>{meta['total']}</strong> finding(s) were identified.
    The overall risk rating is assessed as
    <span style="color:{risk_col};font-weight:700">{risk}</span>.
  </p>
  <div class="summary">{badge_html}</div>
  <h2>Findings ({meta['total']})</h2>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Title</th>
        <th>Target</th><th>Tool</th><th>Detail</th>
      </tr>
    </thead>
    <tbody>
      {rows_html}
    </tbody>
  </table>
  <div class="footer">
    Generated by Exploit Host &mdash; {meta['date']}
  </div>
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)


# ============================================================================
# JSON
# ============================================================================

def _write_json(findings: List[Dict], meta: Dict, path: str):
    payload = {"meta": meta, "findings": findings}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


# ============================================================================
# TXT
# ============================================================================

def _write_txt(findings: List[Dict], meta: Dict, path: str):
    lines = [
        "=" * 70,
        f"  {meta['title'].upper()}",
        "=" * 70,
        f"Target:   {meta['target'] or 'N/A'}",
        f"Operator: {meta['operator'] or 'N/A'}",
        f"Date:     {meta['date']}",
        f"Risk:     {meta['risk']}",
        "",
        "SEVERITY SUMMARY",
        "-" * 40,
    ]
    for s in SEV_ORDER:
        n = meta["counts"].get(s, 0)
        if n:
            lines.append(f"  {s:<10} {n}")
    lines += ["", f"TOTAL FINDINGS: {meta['total']}", "",
              "=" * 70, "FINDINGS", "=" * 70, ""]
    for i, f in enumerate(findings):
        lines += [
            f"[{i+1}] {f.get('severity','?')} | {f.get('title','')}",
            f"    Target : {f.get('target','')}",
            f"    Tool   : {f.get('tool','')}",
            f"    Detail : {str(f.get('detail',''))}",
            "",
        ]
    lines += ["=" * 70,
              f"Generated by Exploit Host - {meta['date']}",
              "=" * 70]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


# ============================================================================
# PDF (reportlab)
# ============================================================================

def _write_pdf(findings: List[Dict], meta: Dict, path: str):
    doc = SimpleDocTemplate(
        path, pagesize=A4,
        leftMargin=2*cm, rightMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )
    styles = getSampleStyleSheet()
    story  = []

    title_style = ParagraphStyle(
        "title", parent=styles["Title"],
        fontSize=24, spaceAfter=6, textColor=colors.HexColor("#1a1a2e")
    )
    story.append(Paragraph(meta["title"], title_style))
    story.append(Paragraph("PENETRATION TEST REPORT", styles["Normal"]))
    story.append(Spacer(1, 0.4*cm))

    risk_col_rl = colors.HexColor(SEV_COLOURS.get(meta["risk"], "#555"))
    meta_data = [
        ["Target",   meta["target"] or "N/A"],
        ["Operator", meta["operator"] or "N/A"],
        ["Date",     meta["date"]],
        ["Risk",     meta["risk"]],
    ]
    meta_table = Table(meta_data, colWidths=[4*cm, 12*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND",  (0,0), (0,-1), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",   (0,0), (0,-1), colors.white),
        ("FONTNAME",    (0,0), (0,-1), "Helvetica-Bold"),
        ("BACKGROUND",  (1,3), (1,3), risk_col_rl),
        ("TEXTCOLOR",   (1,3), (1,3), colors.white),
        ("FONTNAME",    (1,3), (1,3), "Helvetica-Bold"),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("PADDING",     (0,0), (-1,-1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.6*cm))

    story.append(Paragraph("Severity Summary", styles["Heading2"]))
    sum_data = [["Severity", "Count"]]
    for s in SEV_ORDER:
        n = meta["counts"].get(s, 0)
        if n:
            sum_data.append([s, str(n)])
    sum_table = Table(sum_data, colWidths=[6*cm, 4*cm])
    sum_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",  (0,0), (-1,0), colors.white),
        ("FONTNAME",   (0,0), (-1,0), "Helvetica-Bold"),
        ("GRID",       (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("PADDING",    (0,0), (-1,-1), 6),
    ]))
    story.append(sum_table)
    story.append(PageBreak())

    story.append(Paragraph(f"Findings ({meta['total']})", styles["Heading1"]))
    story.append(Spacer(1, 0.3*cm))

    find_data = [["#", "Severity", "Title", "Target", "Tool"]]
    for i, f in enumerate(findings):
        find_data.append([
            str(i+1),
            f.get("severity", "?"),
            f.get("title", "")[:80],
            f.get("target", "")[:40],
            f.get("tool", ""),
        ])

    find_table = Table(
        find_data,
        colWidths=[1*cm, 2.5*cm, 7*cm, 4*cm, 2.5*cm],
        repeatRows=1,
    )
    ts = [
        ("BACKGROUND",  (0,0), (-1,0), colors.HexColor("#1a1a2e")),
        ("TEXTCOLOR",   (0,0), (-1,0), colors.white),
        ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE",    (0,0), (-1,-1), 8),
        ("GRID",        (0,0), (-1,-1), 0.5, colors.lightgrey),
        ("VALIGN",      (0,0), (-1,-1), "TOP"),
        ("PADDING",     (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.white, colors.HexColor("#f4f6f9")]),
    ]
    for i, f in enumerate(findings, start=1):
        sev = f.get("severity", "INFO")
        c   = colors.HexColor(SEV_COLOURS.get(sev, "#555"))
        ts.append(("BACKGROUND", (1,i), (1,i), c))
        ts.append(("TEXTCOLOR",  (1,i), (1,i), colors.white))
        ts.append(("FONTNAME",   (1,i), (1,i), "Helvetica-Bold"))
    find_table.setStyle(TableStyle(ts))
    story.append(find_table)
    story.append(Spacer(1, 0.6*cm))

    story.append(PageBreak())
    story.append(Paragraph("Finding Details", styles["Heading1"]))
    for i, f in enumerate(findings):
        sev  = f.get("severity", "INFO")
        c_rl = colors.HexColor(SEV_COLOURS.get(sev, "#555"))
        story.append(Spacer(1, 0.3*cm))
        story.append(Paragraph(
            f"[{i+1}] {f.get('title','')}",
            ParagraphStyle("fh", parent=styles["Heading3"],
                           textColor=c_rl, fontSize=10)
        ))
        d_rows = [
            ["Severity", sev],
            ["Target",   f.get("target", "")],
            ["Tool",     f.get("tool", "")],
            ["Detail",   str(f.get("detail", ""))[:300]],
        ]
        dt = Table(d_rows, colWidths=[3*cm, 14*cm])
        dt.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f4f6f9")),
            ("FONTNAME",   (0,0), (0,-1), "Helvetica-Bold"),
            ("FONTSIZE",   (0,0), (-1,-1), 8),
            ("GRID",       (0,0), (-1,-1), 0.5, colors.lightgrey),
            ("PADDING",    (0,0), (-1,-1), 5),
            ("VALIGN",     (0,0), (-1,-1), "TOP"),
            ("BACKGROUND", (1,0), (1,0), c_rl),
            ("TEXTCOLOR",  (1,0), (1,0), colors.white),
            ("FONTNAME",   (1,0), (1,0), "Helvetica-Bold"),
        ]))
        story.append(dt)

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(
        f"Generated by Exploit Host — {meta['date']}",
        ParagraphStyle("foot", parent=styles["Normal"],
                       fontSize=8, textColor=colors.grey)
    ))
    doc.build(story)


# ============================================================================
# Helpers
# ============================================================================

def _filter_findings(findings, severity_filter):
    if severity_filter == "critical":
        return [f for f in findings if f.get("severity") == "CRITICAL"]
    if severity_filter == "high_plus":
        return [f for f in findings
                if f.get("severity") in ("CRITICAL", "HIGH")]
    return findings


def _sort_findings(findings):
    order = {s: i for i, s in enumerate(SEV_ORDER)}
    return sorted(findings, key=lambda f: order.get(f.get("severity", "INFO"), 99))


def _count_severities(findings):
    counts = {s: 0 for s in SEV_ORDER}
    for f in findings:
        s = f.get("severity", "INFO")
        if s in counts:
            counts[s] += 1
    return counts


def _risk_rating(counts):
    if counts.get("CRITICAL", 0) > 0: return "CRITICAL"
    if counts.get("HIGH", 0) > 0:     return "HIGH"
    if counts.get("MEDIUM", 0) > 0:   return "MEDIUM"
    if counts.get("LOW", 0) > 0:      return "LOW"
    return "INFO"


def _he(s: str) -> str:
    return (
        str(s)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _emit(on_output, msg):
    print(msg)
    if on_output:
        on_output(msg)
