# ============================================================
# CloudGuardAI - Professional Security Report Generator
# ============================================================

from datetime import datetime
from pathlib import Path
from xml.sax.saxutils import escape
import os
import uuid

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)


# ============================================================
# REPORT DIRECTORY
# ============================================================

REPORT_DIR = Path("reports")

REPORT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


# ============================================================
# HELPERS
# ============================================================

def _safe(value, default="N/A"):
    """
    Safely convert a value into printable text.
    """

    if value is None:
        return default

    if isinstance(value, str):

        value = value.strip()

        return value if value else default

    return str(value)


def _escape(value):
    """
    Escape dynamic values before placing them inside
    ReportLab Paragraph XML.
    """

    return escape(
        _safe(value)
    )


def _format_datetime(value):
    """
    Format scan timestamps for customer-facing reports.
    """

    if not value:
        return "N/A"

    try:

        if isinstance(value, datetime):

            dt = value

        else:

            text = str(value).replace(
                "Z",
                "+00:00"
            )

            dt = datetime.fromisoformat(
                text
            )

        return dt.strftime(
            "%d %b %Y, %H:%M:%S"
        )

    except Exception:

        return _safe(value)


def _number(value):
    """
    Safely convert numeric values.
    """

    try:
        return int(value)

    except (TypeError, ValueError):

        try:
            return round(
                float(value),
                2
            )

        except (TypeError, ValueError):

            return 0


def _severity_value(value):
    """
    Normalize severity values.
    """

    return _safe(
        value,
        "UNKNOWN"
    ).upper()


def _severity_color(severity):
    """
    Return a professional severity color.
    """

    severity = _severity_value(
        severity
    )

    mapping = {

        "CRITICAL": colors.HexColor(
            "#B91C1C"
        ),

        "HIGH": colors.HexColor(
            "#DC2626"
        ),

        "MEDIUM": colors.HexColor(
            "#D97706"
        ),

        "LOW": colors.HexColor(
            "#2563EB"
        ),

        "INFO": colors.HexColor(
            "#64748B"
        ),

        "UNKNOWN": colors.HexColor(
            "#64748B"
        ),
    }

    return mapping.get(
        severity,
        colors.HexColor("#64748B")
    )


def _get_findings(scan):
    """
    Safely retrieve findings.
    """

    findings = scan.get(
        "findings",
        []
    )

    if not isinstance(
        findings,
        list
    ):
        return []

    return findings


def _get_resources(scan):
    """
    Safely retrieve resource statistics.
    """

    resources = scan.get(
        "resources",
        {}
    )

    if not isinstance(
        resources,
        dict
    ):
        return {}

    return resources


# ============================================================
# PAGE HEADER / FOOTER
# ============================================================

def _draw_page(canvas, doc):
    """
    Draw report header and footer on every page.
    """

    canvas.saveState()

    width, height = A4

    # --------------------------------------------------------
    # HEADER
    # --------------------------------------------------------

    canvas.setStrokeColor(
        colors.HexColor("#D7E3F0")
    )

    canvas.line(
        18 * mm,
        height - 18 * mm,
        width - 18 * mm,
        height - 18 * mm,
    )

    canvas.setFont(
        "Helvetica-Bold",
        9
    )

    canvas.setFillColor(
        colors.HexColor("#17324D")
    )

    canvas.drawString(
        18 * mm,
        height - 13 * mm,
        "CloudGuardAI"
    )

    canvas.setFont(
        "Helvetica",
        8
    )

    canvas.setFillColor(
        colors.HexColor("#64748B")
    )

    canvas.drawRightString(
        width - 18 * mm,
        height - 13 * mm,
        "Cloud Security Assessment"
    )

    # --------------------------------------------------------
    # FOOTER
    # --------------------------------------------------------

    canvas.setStrokeColor(
        colors.HexColor("#D7E3F0")
    )

    canvas.line(
        18 * mm,
        15 * mm,
        width - 18 * mm,
        15 * mm,
    )

    canvas.setFont(
        "Helvetica",
        8
    )

    canvas.setFillColor(
        colors.HexColor("#64748B")
    )

    canvas.drawString(
        18 * mm,
        9 * mm,
        "Confidential - CloudGuardAI Security Report"
    )

    canvas.drawRightString(
        width - 18 * mm,
        9 * mm,
        f"Page {doc.page}"
    )

    canvas.restoreState()


# ============================================================
# MAIN PDF GENERATOR
# ============================================================

def generate_pdf(scan):
    """
    Generate a professional CloudGuardAI security report.

    Parameters
    ----------
    scan : dict
        Completed scan document.

    Returns
    -------
    str
        Generated PDF path.
    """

    if not isinstance(
        scan,
        dict
    ):
        raise ValueError(
            "Invalid scan data."
        )

    # ========================================================
    # REPORT METADATA
    # ========================================================

    report_id = uuid.uuid4().hex[:12].upper()

    account = _safe(
        scan.get(
            "account",
            scan.get(
                "account_name",
                scan.get(
                    "aws_account_id",
                    "N/A"
                )
            )
        )
    )

    aws_account_id = _safe(
        scan.get(
            "aws_account_id",
            ""
        ),
        ""
    )

    arn = _safe(
        scan.get(
            "arn",
            ""
        ),
        ""
    )

    risk_score = _number(
        scan.get(
            "risk_score",
            0
        )
    )

    security_level = _safe(
        scan.get(
            "security_level",
            "UNKNOWN"
        )
    )

    security_posture = _safe(
        scan.get(
            "security_posture",
            ""
        ),
        ""
    )

    scan_time = _format_datetime(
        scan.get(
            "scan_time",
            scan.get(
                "created_at",
                ""
            )
        )
    )

    findings = _get_findings(
        scan
    )

    resources = _get_resources(
        scan
    )

    # ========================================================
    # OUTPUT FILE
    # ========================================================

    filename = (
        f"cloudguard_report_"
        f"{report_id}.pdf"
    )

    filepath = (
        REPORT_DIR /
        filename
    )

    # ========================================================
    # DOCUMENT
    # ========================================================

    doc = SimpleDocTemplate(

        str(filepath),

        pagesize=A4,

        rightMargin=18 * mm,

        leftMargin=18 * mm,

        topMargin=25 * mm,

        bottomMargin=22 * mm,

        title=(
            "CloudGuardAI Security Report"
        ),

        author="CloudGuardAI",

        subject=(
            "AWS Cloud Security Assessment"
        ),

        creator="CloudGuardAI",
    )

    # ========================================================
    # STYLES
    # ========================================================

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(

        "ReportTitle",

        parent=styles["Title"],

        fontName="Helvetica-Bold",

        fontSize=23,

        leading=28,

        textColor=colors.HexColor(
            "#17324D"
        ),

        alignment=TA_CENTER,

        spaceAfter=8,
    )

    subtitle_style = ParagraphStyle(

        "ReportSubtitle",

        parent=styles["Normal"],

        fontName="Helvetica",

        fontSize=10,

        leading=15,

        textColor=colors.HexColor(
            "#64748B"
        ),

        alignment=TA_CENTER,

        spaceAfter=18,
    )

    section_style = ParagraphStyle(

        "Section",

        parent=styles["Heading2"],

        fontName="Helvetica-Bold",

        fontSize=15,

        leading=19,

        textColor=colors.HexColor(
            "#17324D"
        ),

        spaceBefore=12,

        spaceAfter=8,
    )

    heading_style = ParagraphStyle(

        "FindingHeading",

        parent=styles["Heading3"],

        fontName="Helvetica-Bold",

        fontSize=10,

        leading=14,

        textColor=colors.HexColor(
            "#17324D"
        ),

        spaceAfter=4,
    )

    body_style = ParagraphStyle(

        "Body",

        parent=styles["BodyText"],

        fontName="Helvetica",

        fontSize=9,

        leading=13,

        textColor=colors.HexColor(
            "#334155"
        ),

        spaceAfter=5,
    )

    small_style = ParagraphStyle(

        "Small",

        parent=styles["BodyText"],

        fontName="Helvetica",

        fontSize=8,

        leading=11,

        textColor=colors.HexColor(
            "#64748B"
        ),
    )

    table_style = ParagraphStyle(

        "Table",

        parent=styles["BodyText"],

        fontName="Helvetica",

        fontSize=8,

        leading=11,

        textColor=colors.HexColor(
            "#334155"
        ),
    )

    table_bold_style = ParagraphStyle(

        "TableBold",

        parent=table_style,

        fontName="Helvetica-Bold",
    )

    # ========================================================
    # STORY
    # ========================================================

    story = []

    # ========================================================
    # COVER / TITLE
    # ========================================================

    story.append(
        Spacer(
            1,
            18 * mm
        )
    )

    story.append(
        Paragraph(
            "CloudGuardAI",
            title_style
        )
    )

    story.append(
        Paragraph(
            "AWS Cloud Security Assessment Report",
            subtitle_style
        )
    )

    # Report metadata card

    metadata_data = [

        [
            Paragraph(
                "<b>Report ID</b>",
                table_bold_style
            ),

            Paragraph(
                _escape(report_id),
                table_style
            ),

            Paragraph(
                "<b>Assessment Time</b>",
                table_bold_style
            ),

            Paragraph(
                _escape(scan_time),
                table_style
            ),
        ],

        [
            Paragraph(
                "<b>AWS Account</b>",
                table_bold_style
            ),

            Paragraph(
                _escape(account),
                table_style
            ),

            Paragraph(
                "<b>Account ID</b>",
                table_bold_style
            ),

            Paragraph(
                _escape(aws_account_id),
                table_style
            ),
        ],

        [
            Paragraph(
                "<b>Security Level</b>",
                table_bold_style
            ),

            Paragraph(
                _escape(security_level),
                table_style
            ),

            Paragraph(
                "<b>Risk Score</b>",
                table_bold_style
            ),

            Paragraph(
                f"<b>{_escape(risk_score)}</b> / 100",
                table_style
            ),
        ],
    ]

    metadata_table = Table(

        metadata_data,

        colWidths=[
            28 * mm,
            55 * mm,
            32 * mm,
            55 * mm,
        ],

        repeatRows=0,
    )

    metadata_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                colors.HexColor("#F5F9FD"),
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.7,
                colors.HexColor("#D7E3F0"),
            ),

            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#E2E8F0"),
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE",
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),

            (
                "RIGHTPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),
        ])
    )

    story.append(
        metadata_table
    )

    story.append(
        Spacer(
            1,
            8 * mm
        )
    )

    # ========================================================
    # EXECUTIVE SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "Executive Summary",
            section_style
        )
    )

    summary_text = (

        "CloudGuardAI performed an automated security "
        "assessment of the connected AWS environment. "
        "The assessment evaluates discovered cloud "
        "resources and security controls and highlights "
        "security conditions that may require attention."
    )

    story.append(
        Paragraph(
            summary_text,
            body_style
        )
    )

    if security_posture:

        story.append(
            Paragraph(
                (
                    f"<b>Security Posture:</b> "
                    f"{_escape(security_posture)}"
                ),
                body_style
            )
        )

    # ========================================================
    # FINDING SUMMARY
    # ========================================================

    severity_counts = {

        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for finding in findings:

        severity = _severity_value(
            finding.get(
                "severity",
                "UNKNOWN"
            )
        )

        if severity not in severity_counts:

            severity_counts[
                "UNKNOWN"
            ] += 1

        else:

            severity_counts[
                severity
            ] += 1

    story.append(
        Paragraph(
            "Finding Summary",
            section_style
        )
    )

    summary_table_data = [

        [
            Paragraph(
                "<b>Severity</b>",
                table_bold_style
            ),

            Paragraph(
                "<b>Findings</b>",
                table_bold_style
            ),
        ]
    ]

    for severity in [
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "UNKNOWN",
    ]:

        summary_table_data.append(

            [
                Paragraph(
                    _escape(severity),
                    table_style
                ),

                Paragraph(
                    str(
                        severity_counts[
                            severity
                        ]
                    ),
                    table_style
                ),
            ]
        )

    summary_table_data.append(

        [
            Paragraph(
                "<b>Total</b>",
                table_bold_style
            ),

            Paragraph(
                f"<b>{len(findings)}</b>",
                table_bold_style
            ),
        ]
    )

    summary_table = Table(

        summary_table_data,

        colWidths=[
            80 * mm,
            80 * mm,
        ],
    )

    summary_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#EAF3FB"),
            ),

            (
                "BACKGROUND",
                (0, -1),
                (-1, -1),
                colors.HexColor("#F5F9FD"),
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.6,
                colors.HexColor("#D7E3F0"),
            ),

            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#E2E8F0"),
            ),

            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "MIDDLE",
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),
        ])
    )

    story.append(
        summary_table
    )

    # ========================================================
    # RESOURCE INVENTORY
    # ========================================================

    story.append(
        Paragraph(
            "AWS Resource Inventory",
            section_style
        )
    )

    resource_rows = [

        [
            Paragraph(
                "<b>Service</b>",
                table_bold_style
            ),

            Paragraph(
                "<b>Resources</b>",
                table_bold_style
            ),
        ]
    ]

    preferred_services = [

        "ec2",
        "s3",
        "iam",
        "cloudtrail",
        "vpc",
        "rds",
        "lambda",
        "kms",
    ]

    for service in preferred_services:

        if service in resources:

            resource_rows.append(

                [
                    Paragraph(
                        _escape(
                            service.upper()
                        ),
                        table_style
                    ),

                    Paragraph(
                        str(
                            _number(
                                resources[
                                    service
                                ]
                            )
                        ),
                        table_style
                    ),
                ]
            )

    if len(resource_rows) == 1:

        resource_rows.append(

            [
                Paragraph(
                    "No resource inventory available",
                    table_style
                ),

                Paragraph(
                    "N/A",
                    table_style
                ),
            ]
        )

    resource_table = Table(

        resource_rows,

        colWidths=[
            80 * mm,
            80 * mm,
        ],
    )

    resource_table.setStyle(
        TableStyle([

            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#EAF3FB"),
            ),

            (
                "BOX",
                (0, 0),
                (-1, -1),
                0.6,
                colors.HexColor("#D7E3F0"),
            ),

            (
                "INNERGRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.HexColor("#E2E8F0"),
            ),

            (
                "LEFTPADDING",
                (0, 0),
                (-1, -1),
                7,
            ),

            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),

            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                6,
            ),
        ])
    )

    story.append(
        resource_table
    )

    # ========================================================
    # FINDINGS
    # ========================================================

    story.append(
        PageBreak()
    )

    story.append(
        Paragraph(
            "Security Findings",
            section_style
        )
    )

    if not findings:

        story.append(
            Paragraph(
                "No security findings were recorded "
                "for this assessment.",
                body_style
            )
        )

    else:

        for index, finding in enumerate(
            findings,
            start=1
        ):

            severity = _severity_value(
                finding.get(
                    "severity",
                    "UNKNOWN"
                )
            )

            issue = _safe(
                finding.get(
                    "issue",
                    "Security finding"
                )
            )

            service = _safe(
                finding.get(
                    "service",
                    "N/A"
                )
            )

            resource = _safe(
                finding.get(
                    "resource",
                    "N/A"
                )
            )

            description = _safe(
                finding.get(
                    "description",
                    ""
                ),
                ""
            )

            impact = _safe(
                finding.get(
                    "impact",
                    ""
                ),
                ""
            )

            recommendation = _safe(
                finding.get(
                    "recommendation",
                    finding.get(
                        "remediation",
                        ""
                    )
                ),
                ""
            )

            evidence = finding.get(
                "evidence",
                ""
            )

            if isinstance(
                evidence,
                dict
            ):

                evidence_text = "; ".join(

                    f"{key}: {value}"

                    for key, value
                    in evidence.items()
                )

            else:

                evidence_text = _safe(
                    evidence,
                    ""
                )

            control_id = _safe(
                finding.get(
                    "control_id",
                    ""
                ),
                ""
            )

            # ------------------------------------------------
            # Finding header
            # ------------------------------------------------

            header = Table(

                [[

                    Paragraph(
                        f"<b>#{index}</b>",
                        table_bold_style
                    ),

                    Paragraph(
                        (
                            f"<b>"
                            f"{_escape(issue)}"
                            f"</b>"
                        ),
                        table_bold_style
                    ),

                    Paragraph(
                        _escape(severity),
                        ParagraphStyle(
                            "Severity",
                            parent=table_style,
                            fontName="Helvetica-Bold",
                            textColor=_severity_color(
                                severity
                            ),
                        )
                    ),

                ]],

                colWidths=[
                    12 * mm,
                    120 * mm,
                    28 * mm,
                ],
            )

            header.setStyle(
                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, -1),
                        colors.HexColor("#F5F9FD"),
                    ),

                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        colors.HexColor("#D7E3F0"),
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "MIDDLE",
                    ),

                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),
                ])
            )

            finding_content = [

                header,

                Spacer(
                    1,
                    2 * mm
                ),

                Paragraph(
                    (
                        f"<b>Service:</b> "
                        f"{_escape(service)}"
                        f"<br/>"
                        f"<b>Resource:</b> "
                        f"{_escape(resource)}"
                    ),
                    body_style
                ),
            ]

            if control_id:

                finding_content.append(

                    Paragraph(
                        (
                            f"<b>Control ID:</b> "
                            f"{_escape(control_id)}"
                        ),
                        body_style
                    )
                )

            if description:

                finding_content.append(

                    Paragraph(
                        (
                            f"<b>Description:</b> "
                            f"{_escape(description)}"
                        ),
                        body_style
                    )
                )

            if impact:

                finding_content.append(

                    Paragraph(
                        (
                            f"<b>Impact:</b> "
                            f"{_escape(impact)}"
                        ),
                        body_style
                    )
                )

            if evidence_text:

                finding_content.append(

                    Paragraph(
                        (
                            f"<b>Evidence:</b> "
                            f"{_escape(evidence_text)}"
                        ),
                        body_style
                    )
                )

            if recommendation:

                finding_content.append(

                    Paragraph(
                        (
                            f"<b>Recommended Action:</b> "
                            f"{_escape(recommendation)}"
                        ),
                        body_style
                    )
                )

            story.append(
                KeepTogether(
                    finding_content
                )
            )

            story.append(
                Spacer(
                    1,
                    5 * mm
                )
            )

    # ========================================================
    # REMEDIATION / GENERATED POLICIES
    # ========================================================

    policies = scan.get(
        "generated_policies",
        []
    )

    if isinstance(
        policies,
        list
    ) and policies:

        story.append(
            PageBreak()
        )

        story.append(
            Paragraph(
                "Generated Remediation Policies",
                section_style
            )
        )

        story.append(
            Paragraph(
                (
                    "The following policy guidance was "
                    "associated with the assessment."
                ),
                body_style
            )
        )

        policy_rows = [

            [
                Paragraph(
                    "<b>Service</b>",
                    table_bold_style
                ),

                Paragraph(
                    "<b>Policy / Guidance</b>",
                    table_bold_style
                ),
            ]
        ]

        for policy in policies:

            if not isinstance(
                policy,
                dict
            ):
                continue

            service = _safe(
                policy.get(
                    "service",
                    "N/A"
                )
            )

            policy_text = _safe(
                policy.get(
                    "policy",
                    policy.get(
                        "description",
                        "N/A"
                    )
                )
            )

            policy_rows.append(

                [
                    Paragraph(
                        _escape(service),
                        table_style
                    ),

                    Paragraph(
                        _escape(policy_text),
                        table_style
                    ),
                ]
            )

        if len(policy_rows) > 1:

            policy_table = Table(

                policy_rows,

                colWidths=[
                    45 * mm,
                    115 * mm,
                ],

                repeatRows=1,
            )

            policy_table.setStyle(
                TableStyle([

                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#EAF3FB"),
                    ),

                    (
                        "BOX",
                        (0, 0),
                        (-1, -1),
                        0.6,
                        colors.HexColor("#D7E3F0"),
                    ),

                    (
                        "INNERGRID",
                        (0, 0),
                        (-1, -1),
                        0.4,
                        colors.HexColor("#E2E8F0"),
                    ),

                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),

                    (
                        "LEFTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),

                    (
                        "RIGHTPADDING",
                        (0, 0),
                        (-1, -1),
                        7,
                    ),

                    (
                        "TOPPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),

                    (
                        "BOTTOMPADDING",
                        (0, 0),
                        (-1, -1),
                        6,
                    ),
                ])
            )

            story.append(
                policy_table
            )

    # ========================================================
    # DISCLAIMER
    # ========================================================

    story.append(
        Spacer(
            1,
            8 * mm
        )
    )

    story.append(
        Paragraph(
            "Report Scope & Disclaimer",
            section_style
        )
    )

    disclaimer = (

        "This report represents the security state observed "
        "during the referenced CloudGuardAI assessment. "
        "Security findings and scores are based on the AWS "
        "resources and permissions available to the scanner "
        "at assessment time. A passing result does not "
        "guarantee that the environment is completely secure. "
        "Organizations should validate findings and apply "
        "changes according to their own operational, security, "
        "and compliance requirements."
    )

    story.append(
        Paragraph(
            disclaimer,
            small_style
        )
    )

    # ========================================================
    # BUILD
    # ========================================================

    doc.build(

        story,

        onFirstPage=_draw_page,

        onLaterPages=_draw_page,
    )

    # ========================================================
    # FINAL VALIDATION
    # ========================================================

    if not filepath.exists():

        raise RuntimeError(
            "PDF file was not generated."
        )

    if filepath.stat().st_size <= 0:

        raise RuntimeError(
            "Generated PDF is empty."
        )

    return str(
        filepath
    )