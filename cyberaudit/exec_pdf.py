"""Branded executive PDF — printable board pack with posture, top risks, charts."""

from __future__ import annotations

import datetime
from pathlib import Path
from typing import Any

from cyberaudit import config
from cyberaudit.posture import compute_posture_score, trend_arrow


def generate_executive_pdf(
    *,
    session_id: str,
    target: str,
    vulns: list[dict],
    hosts_up: list[str],
    open_ports: list[dict],
    previous_posture: float | None = None,
    client_name: str = "",
    logo_path: str | Path | None = None,
) -> Path:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, white
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, Image,
    )
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY

    config.REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    out = config.REPORTS_DIR / f"CyberAudit_Executive_{session_id}.pdf"

    posture = compute_posture_score(
        findings=vulns, hosts_up=len(hosts_up), open_ports=len(open_ports)
    )
    score = posture["posture_score"]
    arrow = trend_arrow(previous_posture, score)

    DARK = HexColor("#0f172a")
    CYAN = HexColor("#0ea5e9")
    SLATE = HexColor("#334155")
    MUTED = HexColor("#64748b")
    LIGHT = HexColor("#f1f5f9")
    BORDER = HexColor("#cbd5e1")
    RED = HexColor("#dc2626")
    AMBER = HexColor("#d97706")
    GREEN = HexColor("#059669")

    page_w, _ = A4
    margin = 0.65 * inch

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="TitleC", fontName="Helvetica-Bold", fontSize=18, textColor=DARK, alignment=TA_CENTER, spaceAfter=4, leading=22))
    styles.add(ParagraphStyle(name="SubC", fontName="Helvetica", fontSize=10, textColor=SLATE, alignment=TA_CENTER, spaceAfter=3, leading=13))
    styles.add(ParagraphStyle(name="H2", fontName="Helvetica-Bold", fontSize=11, textColor=CYAN, spaceBefore=10, spaceAfter=5, leading=14))
    styles.add(ParagraphStyle(name="BodyJ", fontName="Helvetica", fontSize=9, textColor=SLATE, alignment=TA_JUSTIFY, spaceAfter=5, leading=12))
    styles.add(ParagraphStyle(name="Cell", fontName="Helvetica", fontSize=8, textColor=SLATE, leading=10))
    styles.add(ParagraphStyle(name="CellH", fontName="Helvetica-Bold", fontSize=8, textColor=white, leading=10))
    styles.add(ParagraphStyle(name="Small", fontName="Helvetica", fontSize=7.5, textColor=MUTED, alignment=TA_CENTER, leading=9))

    story: list[Any] = []
    company = config.COMPANY

    if logo_path and Path(logo_path).is_file():
        try:
            story.append(Image(str(logo_path), width=1.2 * inch, height=0.5 * inch))
            story.append(Spacer(1, 6))
        except Exception:
            pass

    story.append(Paragraph(company["name"], styles["SubC"]))
    story.append(Paragraph("Network Security Audit — Executive Summary", styles["TitleC"]))
    story.append(Paragraph(f"Prepared for: {client_name or 'Client (authorised engagement)'}", styles["SubC"]))
    story.append(Paragraph(company["tagline"], styles["SubC"]))
    story.append(Spacer(1, 6))
    story.append(HRFlowable(width="100%", thickness=1, color=BORDER, spaceAfter=10))

    meta = [
        [Paragraph("<b>Report ID</b>", styles["Cell"]), Paragraph(session_id, styles["Cell"])],
        [Paragraph("<b>Date</b>", styles["Cell"]), Paragraph(datetime.datetime.now().strftime("%d %B %Y, %H:%M"), styles["Cell"])],
        [Paragraph("<b>Scope</b>", styles["Cell"]), Paragraph(str(target), styles["Cell"])],
        [Paragraph("<b>Contact</b>", styles["Cell"]), Paragraph(f"{company['email']} · {company['phone']}", styles["Cell"])],
    ]
    t = Table(meta, colWidths=[1.3 * inch, 5.2 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 12))

    score_color = GREEN if score >= 75 else (AMBER if score >= 50 else RED)
    score_data = [[
        Paragraph(f"<b>Posture score</b><br/><font size='20'><b>{score:.0f}</b></font>/100", styles["Cell"]),
        Paragraph(f"<b>{posture['band']}</b><br/>{posture['band_note']}<br/>Trend: {arrow}", styles["Cell"]),
        Paragraph(f"Hosts: <b>{len(hosts_up)}</b><br/>Services: <b>{len(open_ports)}</b><br/>Findings: <b>{len(vulns)}</b>", styles["Cell"]),
    ]]
    st = Table(score_data, colWidths=[2.0 * inch, 2.8 * inch, 1.7 * inch])
    st.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("BOX", (0, 0), (-1, -1), 1.5, score_color),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(st)
    story.append(Spacer(1, 8))

    counts = posture["counts"]
    story.append(Paragraph("Finding severity distribution", styles["H2"]))
    chart_rows = [
        [Paragraph(h, styles["CellH"]) for h in ("Critical", "High", "Medium", "Low")],
        [Paragraph(str(counts[k]), styles["Cell"]) for k in ("critical", "high", "medium", "low")],
    ]
    ct = Table(chart_rows, colWidths=[1.6 * inch] * 4)
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), RED),
        ("BACKGROUND", (1, 0), (1, 0), HexColor("#ea580c")),
        ("BACKGROUND", (2, 0), (2, 0), AMBER),
        ("BACKGROUND", (3, 0), (3, 0), HexColor("#65a30d")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(ct)
    story.append(Spacer(1, 8))

    story.append(Paragraph("Top risks for leadership", styles["H2"]))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_v = sorted(vulns, key=lambda v: (order.get((v.get("severity") or "").lower(), 9), -(v.get("cvss_base_score") or 0)))
    top = sorted_v[:5]
    if not top:
        story.append(Paragraph("No major service-exposure issues were flagged in this scan window.", styles["BodyJ"]))
    else:
        head = [Paragraph(h, styles["CellH"]) for h in ("#", "Severity", "CVSS 4.0", "Where", "Issue")]
        rows = [head]
        for i, v in enumerate(top, 1):
            rows.append([
                Paragraph(str(i), styles["Cell"]),
                Paragraph((v.get("severity") or "").upper(), styles["Cell"]),
                Paragraph(f"{v.get('cvss_base_score', '—')} ({v.get('cvss_severity', '')})", styles["Cell"]),
                Paragraph(f"{v.get('host')}:{v.get('port')}", styles["Cell"]),
                Paragraph(str(v.get("title") or "")[:80], styles["Cell"]),
            ])
        rt = Table(rows, colWidths=[0.35 * inch, 0.85 * inch, 1.1 * inch, 1.4 * inch, 2.8 * inch])
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), DARK),
            ("GRID", (0, 0), (-1, -1), 0.4, BORDER),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [white, LIGHT]),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        story.append(rt)

    story.append(Paragraph("What this means", styles["H2"]))
    story.append(Paragraph(
        "This is a point-in-time network audit under authorised rules of engagement. "
        "It maps devices and services that responded during the scan window. "
        "It is not continuous monitoring. Posture scores help you track improvement "
        "after remediation — schedule a retest to prove closed items to the board.",
        styles["BodyJ"],
    ))
    story.append(Paragraph("Recommended next steps", styles["H2"]))
    story.append(Paragraph(
        "1. Assign an owner for each Critical and High finding.<br/>"
        "2. Restrict unnecessary services at the firewall.<br/>"
        "3. Enforce MFA on remote access (VPN, RDP, SSH).<br/>"
        "4. Test backups — keep an offline or immutable copy.<br/>"
        "5. Book a CyberAudit retest after remediation to generate a delta report.",
        styles["BodyJ"],
    ))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=0.5, color=BORDER))
    story.append(Paragraph(
        f"{company['name']} · {company['address']} · {company['email']} · {company['phone']}<br/>"
        f"Computer Misuse Act Chap. 11:17 context is indicative — not a legal opinion. "
        f"CVSS 4.0 scores are CyberAudit estimates for prioritisation.",
        styles["Small"],
    ))

    def _footer(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        canvas.setFillColor(MUTED)
        canvas.drawString(margin, 0.4 * inch, "TrinTech Digital Defense — Confidential")
        canvas.drawRightString(page_w - margin, 0.4 * inch, f"Page {doc.page}")
        canvas.restoreState()

    doc = SimpleDocTemplate(
        str(out), pagesize=A4,
        leftMargin=margin, rightMargin=margin,
        topMargin=0.55 * inch, bottomMargin=0.6 * inch,
        title=f"CyberAudit Executive — {session_id}",
        author=company["name"],
    )
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return out
