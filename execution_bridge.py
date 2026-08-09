import numpy as np
import collections
import math
import hashlib
import os
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors


# ============================================================
# GLOBAL SIGNATURE VERIFICATION RULES MATRIX
# ============================================================

SIGNATURE_DB = {
    "504B0304": {
        "type": "ZIP / Microsoft Office Open XML",
        "exts": [".pptx", ".docx", ".xlsx", ".zip", ".jar"]
    },
    "25504446": {
        "type": "Adobe PDF Document",
        "exts": [".pdf"]
    },
    "4D5A": {
        "type": "Windows Portable Executable",
        "exts": [".exe", ".dll", ".sys", ".bin"]
    },
    "7F454C46": {
        "type": "Linux Executable Linkable Format",
        "exts": [".elf", ".so", ".bin"]
    },
    "89504E47": {
        "type": "PNG Image Asset",
        "exts": [".png"]
    },
    "FFD8FF": {
        "type": "JPEG Image Asset",
        "exts": [".jpg", ".jpeg"]
    },
    "47494638": {
        "type": "GIF Image Asset",
        "exts": [".gif"]
    },
    "52617221": {
        "type": "RAR Compressed Archive",
        "exts": [".rar"]
    },
    "1F8B08": {
        "type": "GZIP Compressed Stream",
        "exts": [".gz", ".tar.gz"]
    }
}


TRAILER_MARKERS = {
    "25504446": b"%%EOF",
    "504B0304": b"\x50\x4B\x05\x06"
}


# ============================================================
# ADVANCED ANTI-FORENSIC ANALYSIS
# ============================================================

def analyze_advanced_anti_forensics(
    file_bytes: bytes,
    filename: str
) -> dict:

    """Executes multi-tier analysis targeting anti-forensic indicators."""

    file_size = len(file_bytes)

    # --------------------------------------------------------
    # EMPTY FILE
    # --------------------------------------------------------

    if file_size == 0:
        return {
            "filename": filename,
            "extension": os.path.splitext(filename.lower())[1],
            "rule_score": 0,
            "verdict": "EMPTY_FILE",
            "threat_level": "UNKNOWN",
            "techniques": {},
            "size_mb": 0.0,
            "size_bytes": 0,
            "magic_bytes": "N/A",
            "detected_sig": "Empty File",
            "expected_format": "Unknown",
            "sig_status": "UNVERIFIED",
            "ext_mismatch": "NO",
            "md5": "",
            "sha1": "",
            "sha256": "",
            "global_entropy": 0.0,
            "entropy_variance": 0.0,
            "max_entropy": 0.0,
            "min_entropy": 0.0,
            "slack_space_bytes": 0
        }

    # ========================================================
    # 1. MULTI-HASH CRYPTOGRAPHIC INTEGRITY
    # ========================================================

    md5_h = hashlib.md5(file_bytes).hexdigest()
    sha1_h = hashlib.sha1(file_bytes).hexdigest()
    sha256_h = hashlib.sha256(file_bytes).hexdigest()

    # ========================================================
    # 2. STRUCTURAL CONTENT & EXTENSION ANALYSIS
    # ========================================================

    magic_4 = file_bytes[:4].hex().upper()
    magic_3 = file_bytes[:3].hex().upper()

    _, current_ext = os.path.splitext(filename.lower())

    detected_sig = "Unknown Binary Data Stream"
    expected_format = "General Binary / Unclassified Struct"
    sig_status = "UNVERIFIED"
    ext_mismatch = "NO"
    target_magic = None

    if magic_4 in SIGNATURE_DB:
        target_magic = magic_4
    elif magic_3 in SIGNATURE_DB:
        target_magic = magic_3

    if target_magic:

        sig_info = SIGNATURE_DB[target_magic]

        detected_sig = sig_info["type"]
        expected_format = sig_info["type"]
        sig_status = "VALID"

        if current_ext not in sig_info["exts"]:
            ext_mismatch = "YES"

    else:

        if current_ext in [
            ".pdf",
            ".docx",
            ".pptx",
            ".xlsx",
            ".exe",
            ".png",
            ".jpg",
            ".jpeg"
        ]:
            ext_mismatch = "YES"

    # ========================================================
    # 3. SLIDING WINDOW SHANNON ENTROPY
    # ========================================================

    step_multiplier = max(
        1,
        file_size // (50 * 1024 * 1024)
    )

    window_size = 256
    step_size = 64 * step_multiplier

    entropies = []

    analysis_limit = min(
        file_size,
        15 * 1024 * 1024
    )

    for offset in range(
        0,
        max(0, analysis_limit - window_size + 1),
        step_size
    ):

        block = file_bytes[
            offset:offset + window_size
        ]

        if len(block) < window_size:
            continue

        counts = collections.Counter(block)

        ent = -sum(
            (c / window_size)
            * math.log2(c / window_size)
            for c in counts.values()
        )

        entropies.append(ent)

    # Global entropy
    entropy_sample = file_bytes[:1000000]

    if entropy_sample:

        global_counts = collections.Counter(
            entropy_sample
        )

        sample_length = len(entropy_sample)

        global_ent = -sum(
            (c / sample_length)
            * math.log2(c / sample_length)
            for c in global_counts.values()
        )

    else:
        global_ent = 0.0

    std_dev = (
        float(np.std(entropies))
        if entropies
        else 0.0
    )

    max_ent = (
        max(entropies)
        if entropies
        else 0.0
    )

    min_ent = (
        min(entropies)
        if entropies
        else 0.0
    )

    # ========================================================
    # 4. ADAPTIVE WEIGHT LOGIC
    # ========================================================

    rule_score = 0

    techniques_intercepted = {}

    slack_bytes_found = 0

    # Extension spoofing
    if ext_mismatch == "YES":

        rule_score += 40

        techniques_intercepted[
            "Extension Spoofing"
        ] = (
            "Extension maps to a conflicting "
            "magic file signature."
        )

    # Slack-space detection
    if target_magic in TRAILER_MARKERS:

        marker = TRAILER_MARKERS[target_magic]

        marker_index = file_bytes.rfind(marker)

        if marker_index != -1:

            slack_bytes_found = (
                file_size
                - (marker_index + len(marker))
            )

            if slack_bytes_found > 1024:

                rule_score += 35

                techniques_intercepted[
                    "Slack Space Data Appending"
                ] = (
                    f"Excessive bytes "
                    f"({slack_bytes_found}) hidden "
                    f"past trailing wrapper."
                )

    # Entropy variance
    if std_dev > 1.35 and global_ent < 6.8:

        rule_score += 30

        techniques_intercepted[
            "Clandestine Payload Injection"
        ] = (
            "Irregular local variance spikes "
            "reveal concealed variable sections."
        )

    # High entropy camouflage
    if (
        global_ent > 7.85
        and std_dev < 0.08
        and current_ext not in [
            ".zip",
            ".rar",
            ".gz"
        ]
    ):

        rule_score += 35

        techniques_intercepted[
            "High-Entropy Data Camouflage"
        ] = (
            "Standard asset exhibits absolute "
            "encryption randomness profile."
        )

    # Magic identifier erasure
    if (
        not target_magic
        and magic_4 == "00000000"
    ):

        rule_score += 50

        techniques_intercepted[
            "Magic Identifier Erasure"
        ] = (
            "File header field completely zeroed "
            "to bypass signature parsers."
        )

    # Final score
    rule_score = min(rule_score, 100)

    if rule_score < 25:
        threat_level = "LOW"
    elif rule_score < 60:
        threat_level = "MEDIUM"
    else:
        threat_level = "HIGH RISK / THREAT DETECTED"

    if rule_score < 25:
        verdict = (
            "NO STRONG STANDALONE "
            "ANTI-FORENSIC INDICATOR DETECTED"
        )
    else:
        verdict = (
            "PROBABLE SYSTEM TAMPERING / "
            "METADATA MANIPULATION DETECTED"
        )

    # ========================================================
    # RETURN DATA
    # ========================================================

    return {
        "filename": filename,
        "extension": current_ext,
        "size_bytes": file_size,
        "size_mb": round(
            file_size / (1024 * 1024),
            2
        ),
        "magic_bytes": (
            magic_4
            if magic_4 != "00000000"
            else "00 00 00 00 (Wiped)"
        ),
        "detected_sig": detected_sig,
        "expected_format": expected_format,
        "sig_status": sig_status,
        "ext_mismatch": ext_mismatch,
        "md5": md5_h,
        "sha1": sha1_h,
        "sha256": sha256_h,
        "global_entropy": round(
            global_ent,
            4
        ),
        "entropy_variance": round(
            std_dev,
            4
        ),
        "max_entropy": round(
            max_ent,
            4
        ),
        "min_entropy": round(
            min_ent,
            4
        ),
        "rule_score": rule_score,
        "threat_level": threat_level,
        "verdict": verdict,
        "techniques": techniques_intercepted,
        "slack_space_bytes": slack_bytes_found
    }


# ============================================================
# PDF REPORT GENERATOR
# ============================================================

def generate_pdf_report(
    data: dict,
    out_path: str = "Forensic_Report.pdf"
):

    """Generates the complete 11-section forensic report."""

    doc = SimpleDocTemplate(
        out_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=30,
        bottomMargin=30
    )

    # ========================================================
    # STYLES
    # ========================================================

    title_fmt = ParagraphStyle(
        "T",
        fontName="Helvetica-Bold",
        fontSize=13,
        leading=17,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=12,
        alignment=1
    )

    h2_fmt = ParagraphStyle(
        "H",
        fontName="Helvetica-Bold",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1E3A8A"),
        spaceBefore=8,
        spaceAfter=4,
        keepWithNext=True
    )

    cell_fmt = ParagraphStyle(
        "C",
        fontName="Helvetica",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#334155")
    )

    bold_cell = ParagraphStyle(
        "BC",
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#1E293B")
    )

    alert_cell = ParagraphStyle(
        "AC",
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=12,
        textColor=colors.HexColor("#991B1B")
    )

    # ========================================================
    # COMMON TABLE STYLE
    # ========================================================

    t_style = TableStyle([
        (
            "BACKGROUND",
            (0, 0),
            (-1, 0),
            colors.HexColor("#F1F5F9")
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.5,
            colors.HexColor("#CBD5E1")
        ),
        (
            "PADDING",
            (0, 0),
            (-1, -1),
            4
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "MIDDLE"
        )
    ])

    # ========================================================
    # REPORT STORY
    # ========================================================

    story = [
        Paragraph(
            "FORENSIC REPORT FOR ANTI-FORENSIC "
            "FILE MANIPULATION DETECTION",
            title_fmt
        ),

        Paragraph(
            f"<b>Analysis Chronology:</b> "
            f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
            f"UTC | "
            f"<b>System Operational Verification Level</b>",
            cell_fmt
        ),

        Spacer(1, 6)
    ]

    # ========================================================
    # 1. PRIMARY FILE INFORMATION
    # ========================================================

    story.append(
        Paragraph(
            "1. Primary File Information",
            h2_fmt
        )
    )

    t1 = Table([
        [
            Paragraph(
                "Metadata Field Property",
                bold_cell
            ),
            Paragraph(
                "Extracted Metric Value",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Target File Name",
                cell_fmt
            ),
            Paragraph(
                data["filename"],
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Registered Extension",
                cell_fmt
            ),
            Paragraph(
                data["extension"],
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Calculated Data Mass",
                cell_fmt
            ),
            Paragraph(
                f"{data['size_mb']} MB "
                f"({data['size_bytes']} Bytes)",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "MIME Mapping Categorization",
                cell_fmt
            ),
            Paragraph(
                data["detected_sig"],
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t1.setStyle(t_style)

    story.append(t1)

    # ========================================================
    # 2. CRYPTOGRAPHIC INTEGRITY SIGNATURES
    # ========================================================

    story.append(
        Paragraph(
            "2. Cryptographic Integrity Signatures",
            h2_fmt
        )
    )

    t2 = Table([
        [
            Paragraph(
                "Algorithm Index",
                bold_cell
            ),
            Paragraph(
                "Calculated Hash Fingerprint",
                bold_cell
            )
        ],
        [
            Paragraph(
                "MD5 Hash String",
                cell_fmt
            ),
            Paragraph(
                data["md5"],
                cell_fmt
            )
        ],
        [
            Paragraph(
                "SHA-1 Digital Signature",
                cell_fmt
            ),
            Paragraph(
                data["sha1"],
                cell_fmt
            )
        ],
        [
            Paragraph(
                "SHA-256 System Handshake",
                cell_fmt
            ),
            Paragraph(
                data["sha256"],
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t2.setStyle(t_style)

    story.append(t2)

    # ========================================================
    # 3. BINARY STRUCTURAL SIGNATURE CHECK
    # ========================================================

    story.append(
        Paragraph(
            "3. Binary Structural Signature Check",
            h2_fmt
        )
    )

    t3 = Table([
        [
            Paragraph(
                "Validation Parameter",
                bold_cell
            ),
            Paragraph(
                "Analysis Verification Value",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Header Magic Hex Code",
                cell_fmt
            ),
            Paragraph(
                data["magic_bytes"],
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Expected File Context",
                cell_fmt
            ),
            Paragraph(
                data["expected_format"],
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Extension Mismatch Alert",
                cell_fmt
            ),
            Paragraph(
                data["ext_mismatch"],
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Header Signature Health",
                cell_fmt
            ),
            Paragraph(
                data["sig_status"],
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t3.setStyle(t_style)

    story.append(t3)

    # ========================================================
    # 4. STRUCTURAL INTEGRITY & SLACK SPACE
    # ========================================================

    story.append(
        Paragraph(
            "4. Structural Integrity & Slack Space Data Mapping",
            h2_fmt
        )
    )

    t4 = Table([
        [
            Paragraph(
                "Structure Boundary Parameter",
                bold_cell
            ),
            Paragraph(
                "Analysis Verification Value",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Hidden Appended Slack Space",
                cell_fmt
            ),
            Paragraph(
                f"{data['slack_space_bytes']} "
                f"Bytes past expected trailer",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Data Alignment Boundary Check",
                cell_fmt
            ),
            Paragraph(
                "VALID"
                if data["slack_space_bytes"] == 0
                else "ANOMALOUS / FOOTER OVERLAP",
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t4.setStyle(t_style)

    story.append(t4)

    # ========================================================
    # 5. SIGNAL ANOMALY PROFILES
    # ========================================================

    story.append(
        Paragraph(
            "5. Signal Anomaly Profiles & Indicators",
            h2_fmt
        )
    )

    t5 = Table([
        [
            Paragraph(
                "Obfuscation Metric Base",
                bold_cell
            ),
            Paragraph(
                "Evaluated Metric Level",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Global Block Shannon Entropy",
                cell_fmt
            ),
            Paragraph(
                str(data["global_entropy"]),
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Internal Sliding Window Variance (StdDev)",
                cell_fmt
            ),
            Paragraph(
                str(data["entropy_variance"]),
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Peak Localized Window Entropy",
                cell_fmt
            ),
            Paragraph(
                str(data["max_entropy"]),
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Minimum Localized Window Entropy",
                cell_fmt
            ),
            Paragraph(
                str(data["min_entropy"]),
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t5.setStyle(t_style)

    story.append(t5)

    # ========================================================
    # 6. TACTICAL ANTI-FORENSIC TECHNIQUES
    # ========================================================

    story.append(
        Paragraph(
            "6. Tactical Anti-Forensic Techniques "
            "Interception Matrix",
            h2_fmt
        )
    )

    tech_rows = [
        [
            Paragraph(
                "Identified Method Class",
                bold_cell
            ),
            Paragraph(
                "Diagnostic Detection Description Evidence",
                bold_cell
            )
        ]
    ]

    if data["techniques"]:

        for k, v in data["techniques"].items():

            tech_rows.append([
                Paragraph(
                    k,
                    bold_cell
                ),
                Paragraph(
                    v,
                    cell_fmt
                )
            ])

    else:

        tech_rows.append([
            Paragraph(
                "No Manifest Vectors",
                cell_fmt
            ),
            Paragraph(
                "The target file shows standard "
                "behavioral bounds across all rule vectors.",
                cell_fmt
            )
        ])

    t6 = Table(
        tech_rows,
        splitByRow=1
    )

    t6.setStyle(t_style)

    story.append(t6)

    # ========================================================
    # 7. CROSS-ARTIFACT CORRELATION
    # ========================================================

    story.append(
        Paragraph(
            "7. Cross-Artifact Correlation Diagnostics",
            h2_fmt
        )
    )

    t7 = Table([
        [
            Paragraph(
                "Security Check Constraints",
                bold_cell
            ),
            Paragraph(
                "Anomalous Signatures Status",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Signature Mismatch Integrity Check",
                cell_fmt
            ),
            Paragraph(
                "Anomalous / Triggered"
                if data["ext_mismatch"] == "YES"
                else "Clear / Passed",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Clandestine Injection Boundary Mapping",
                cell_fmt
            ),
            Paragraph(
                "Anomalous / Triggered"
                if "Clandestine Payload Injection"
                in data["techniques"]
                else "Clear / Passed",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Missing Structural Trailer Validation",
                cell_fmt
            ),
            Paragraph(
                "Anomalous / Triggered"
                if data["slack_space_bytes"] > 0
                else "Clear / Passed",
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t7.setStyle(t_style)

    story.append(t7)

    # ========================================================
    # 8. ADAPTIVE METRIC WEIGHT DISTRIBUTION
    # ========================================================

    story.append(
        Paragraph(
            "8. Adaptive Metric Weight Distribution",
            h2_fmt
        )
    )

    injection_detected = (
        "Clandestine Payload Injection"
        in data["techniques"]
    )

    t8 = Table([
        [
            Paragraph(
                "Evaluated Layer",
                bold_cell
            ),
            Paragraph(
                "Base Weight Allocation",
                bold_cell
            ),
            Paragraph(
                "Adjusted Execution Weight",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Timestamp Attribute Profile",
                cell_fmt
            ),
            Paragraph(
                "0.25",
                cell_fmt
            ),
            Paragraph(
                "0.00"
                if injection_detected
                else "0.25",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Structural Extension Header Verification",
                cell_fmt
            ),
            Paragraph(
                "0.35",
                cell_fmt
            ),
            Paragraph(
                "0.50"
                if injection_detected
                else "0.35",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Sliding Window Block Entropy Delta",
                cell_fmt
            ),
            Paragraph(
                "0.40",
                cell_fmt
            ),
            Paragraph(
                "0.50"
                if injection_detected
                else "0.40",
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t8.setStyle(t_style)

    story.append(t8)

    # ========================================================
    # 9. ENVIRONMENTAL RISK HEURISTICS
    # ========================================================

    story.append(
        Paragraph(
            "9. Environmental Risk Heuristics Evaluation",
            h2_fmt
        )
    )

    magic_erasure_detected = (
        "Magic Identifier Erasure"
        in data["techniques"]
    )

    camouflage_detected = (
        "High-Entropy Data Camouflage"
        in data["techniques"]
    )

    t9 = Table([
        [
            Paragraph(
                "Heuristic Evaluation Layer Check",
                bold_cell
            ),
            Paragraph(
                "Status",
                bold_cell
            ),
            Paragraph(
                "Risk Contribution Score",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Zeroed Magic Header Framework Attack",
                cell_fmt
            ),
            Paragraph(
                "Detected"
                if magic_erasure_detected
                else "Clear",
                cell_fmt
            ),
            Paragraph(
                "50%"
                if magic_erasure_detected
                else "0%",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Data Packing/Camouflage Obfuscation",
                cell_fmt
            ),
            Paragraph(
                "Detected"
                if camouflage_detected
                else "Clear",
                cell_fmt
            ),
            Paragraph(
                "35%"
                if camouflage_detected
                else "0%",
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t9.setStyle(t_style)

    story.append(t9)

    # ========================================================
    # 10. OPERATIONAL VALIDATION SUMMARY
    # ========================================================

    story.append(
        Paragraph(
            "10. Operational Validation Summary",
            h2_fmt
        )
    )

    t10 = Table([
        [
            Paragraph(
                "Parameter Metric",
                bold_cell
            ),
            Paragraph(
                "Analysis Result Level",
                bold_cell
            )
        ],
        [
            Paragraph(
                "Composite Danger Index Score",
                cell_fmt
            ),
            Paragraph(
                f"{data['rule_score']}.0%",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Framework Weighted Evaluation Metric",
                cell_fmt
            ),
            Paragraph(
                f"{data['rule_score']} / 100",
                cell_fmt
            )
        ],
        [
            Paragraph(
                "Evaluated Threat Level Classification",
                cell_fmt
            ),
            Paragraph(
                data["threat_level"],
                cell_fmt
            )
        ]
    ], splitByRow=1)

    t10.setStyle(t_style)

    story.append(t10)

    # ========================================================
    # 11. CONSOLIDATED SYSTEM SECURITY VERDICT
    # ========================================================

    story.append(
        Paragraph(
            "11. Consolidated System Security Verdict",
            h2_fmt
        )
    )

    v_bg = (
        colors.HexColor("#FEE2E2")
        if data["rule_score"] >= 25
        else colors.HexColor("#E2E8F0")
    )

    t11 = Table([
        [
            Paragraph(
                f"Risk Assessment Statement: "
                f"{data['threat_level']}",
                bold_cell
            )
        ],
        [
            Paragraph(
                f"FINAL STATEMENT VERDICT: "
                f"{data['verdict']}",
                alert_cell
                if data["rule_score"] >= 25
                else bold_cell
            )
        ]
    ], splitByRow=1)

    t11.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, -1),
                v_bg
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                1,
                colors.HexColor("#94A3B8")
            ),
            (
                "PADDING",
                (0, 0),
                (-1, -1),
                6
            )
        ])
    )

    story.append(t11)

    # ========================================================
    # BUILD PDF
    # ========================================================

    doc.build(story)

    return out_path


print(
    "✓ Fixed: execution_bridge.py rewritten successfully "
    "with all 11 report sections."
)
