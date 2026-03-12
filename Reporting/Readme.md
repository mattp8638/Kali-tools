Reporting Phase — Full Tool Plan
Category 1 — Data Normalisation
Before any report is generated, raw tool output needs to be standardised into a unified finding schema. Pure Python.

Tool	What it does
finding_normaliser.py	Takes raw output from any tool across all phases and maps it to a standard Finding schema: id, title, phase, severity (Critical/High/Medium/Low/Info), cvss_score, description, evidence, affected_target, remediation
severity_ranker.py	Sorts and deduplicates findings across all phases by CVSS score, collapses duplicates from multiple tools that found the same issue, produces a prioritised finding list
evidence_packager.py	Collects raw stdout, screenshots references, request/response pairs, and PoC command output into a structured evidence bundle per finding
Category 2 — Report Generation
Pure Python — jinja2 for templates, reportlab or weasyprint for PDF, openpyxl for Excel.

| Tool | Kali Equivalent | What it does |
|---|---|
| report_html.py | Manual | Generates a full interactive HTML report with collapsible sections per finding, severity colour coding, evidence tabs, executive summary, and remediation table — using jinja2 templates |
| report_pdf.py | Manual | Renders the HTML report to PDF via weasyprint — produces a professional-grade pentest report document |
| report_csv.py | Manual | Flat CSV export of all findings — tool, phase, severity, CVSS, title, affected target, remediation — for import into vulnerability management platforms |
| report_json.py | Manual | Full structured JSON export of all findings with evidence — machine-readable, feeds into Jira/ServiceNow/Splunk integrations |
| report_excel.py | Manual | Multi-sheet Excel workbook via openpyxl — Executive Summary sheet, Findings sheet, Remediation Tracker sheet, Risk Matrix sheet |
| report_markdown.py | Manual | Clean Markdown report — suitable for GitHub wiki, Confluence, or Notion — with finding tables, severity badges, and code blocks for PoC commands |

Category 3 — Report Sections (Building Blocks)
These are components assembled by the generators above. Pure Python.

Component	What it contains
section_executive_summary.py	Non-technical 1-page summary — engagement scope, overall risk rating, top 3 critical findings, business impact statement
section_methodology.py	Documents which tools ran, which phases completed, what was tested and what was out of scope
section_findings.py	Per-finding detail — description, CVSS breakdown, evidence, affected URL/host/port, reproduction steps, remediation guidance
section_remediation_plan.py	Prioritised remediation roadmap — immediate (Critical/High), short-term (Medium), long-term (Low/Info), with effort estimates
section_risk_matrix.py	5×5 likelihood vs impact risk matrix — generates both the data and an SVG/HTML visual
section_retest_checklist.py	Auto-generates a retest checklist from confirmed findings — tick-box format for re-verification after remediation
Category 4 — Delivery & Integration
Pure Python.

Tool	What it does
report_emailer.py	Sends the completed report package (PDF + CSV) via smtplib with TLS — to a configured recipient list
jira_export.py	Creates Jira issues from findings via Jira REST API — one issue per finding, severity mapped to priority, evidence in description
defectdojo_export.py	Pushes findings to DefectDojo (the industry-standard open-source vuln management platform) via its REST API
report_differ.py	Compares two JSON reports from different engagements — highlights new findings, remediated findings, and regression findings
Category 5 — Master Orchestrator
Tool	Purpose
full_report_profile.py	Takes the output of all four phase profiles as input, runs the full normalisation → ranking → evidence packaging → report generation pipeline, produces the complete report package in all formats simultaneously
Python Dependencies Needed
Library	Used By	Install
jinja2	HTML/Markdown report templates	pip install jinja2
weasyprint	PDF rendering from HTML	pip install weasyprint
reportlab	Alternative PDF if WeasyPrint not viable on Windows	pip install reportlab
openpyxl	Excel report	pip install openpyxl
requests	Jira, DefectDojo API integrations	Already installed
Recommended Build Order
text
1.  finding_normaliser.py         ← must be first, everything depends on it
2.  severity_ranker.py            ← feeds all report generators
3.  report_json.py                ← pure Python, no new deps, validates schema
4.  report_csv.py                 ← pure Python, immediate usability
5.  report_markdown.py            ← jinja2 only, lightweight
6.  section_executive_summary.py  ← needed by HTML/PDF
7.  section_findings.py           ← needed by HTML/PDF
8.  section_remediation_plan.py   ← needed by HTML/PDF
9.  section_risk_matrix.py        ← SVG risk matrix
10. report_html.py                ← jinja2 full report
11. report_pdf.py                 ← weasyprint (heaviest dep)
12. report_excel.py               ← openpyxl
13. evidence_packager.py          ← bundles raw evidence per finding
14. section_methodology.py        ← documents test coverage
15. section_retest_checklist.py   ← post-remediation checklist
16. report_emailer.py             ← smtplib (stdlib)
17. report_differ.py              ← engagement-to-engagement comparison
18. jira_export.py                ← optional integration
19. defectdojo_export.py          ← optional integration
20. full_report_profile.py        ← orchestrator, last
Complete 5-Phase Summary
Now that all phases are planned, here's the full picture of what you're building:

Phase	Tools	New Deps
Recon	~25 tools	Already done
Scanning	18 tools	Already done
VA	16 tools	beautifulsoup4, lxml, PyJWT
Exploitation	18 tools	Zero new
Reporting	20 tools	jinja2, weasyprint, openpyxl