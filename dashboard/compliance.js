"use strict";

/*
 * Nanobricks Endpoint360
 * Security Compliance Dashboard v0.1.0
 *
 * Read-only visualization of the latest compliance report.
 */

document.addEventListener("DOMContentLoaded", async () => {
    const API = "/api/latest-compliance";

    const element = (id) => document.getElementById(id);

    const setText = (id, value) => {
        const target = element(id);
        if (target) {
            target.textContent = String(value);
        }
    };

    const showMessage = (message) => {
        const body = element("compliance-table-body");
        if (!body) return;

        body.replaceChildren();

        const row = document.createElement("tr");
        const cell = document.createElement("td");

        cell.colSpan = 4;
        cell.textContent = message;

        row.appendChild(cell);
        body.appendChild(row);
    };

    const setStatus = (message, type) => {
        const badge = element("compliance-status");
        if (!badge) return;

        badge.textContent = message;
        badge.className = "status " + type;
    };

    const addCell = (row, value) => {
        const cell = document.createElement("td");
        cell.textContent = String(value ?? "Not available");
        row.appendChild(cell);
        return cell;
    };

    const render = (report) => {
        if (
            !report ||
            report.Module !== "Security Compliance" ||
            !report.Summary ||
            !Array.isArray(report.Checks)
        ) {
            throw new Error("Invalid compliance report structure");
        }

        const summary = report.Summary;

        const score = summary.ComplianceScore;

        const scoreText =
            typeof score === "number" && Number.isFinite(score)
                ? score.toFixed(1) + "%"
                : "Not assessed";

        setText("compliance-score", scoreText);
        setText(
            "compliance-evaluated",
            summary.Evaluated ?? "Not available"
        );

        setText("compliance-pass", summary.Pass ?? 0);
        setText("compliance-fail", summary.Fail ?? 0);
        setText("compliance-warning", summary.Warning ?? 0);
        setText(
            "compliance-not-assessed",
            summary.NotAssessed ?? 0
        );

        const body = element("compliance-table-body");
        if (!body) return;

        body.replaceChildren();

        for (const check of report.Checks) {
            const row = document.createElement("tr");

            addCell(row, check.Control);

            const statusCell = document.createElement("td");
            const badge = document.createElement("span");

            const status = String(check.Result ?? "Not Assessed");

            const types = {
                "Pass": "collected",
                "Fail": "failed",
                "Warning": "attention",
                "Not Assessed": "restricted"
            };

            badge.className =
                "status " + (types[status] || "unknown");

            badge.textContent = status;
            statusCell.appendChild(badge);
            row.appendChild(statusCell);

            addCell(row, check.Evidence);
            addCell(row, check.Recommendation);

            body.appendChild(row);
        }

        if (report.Checks.length === 0) {
            showMessage("No compliance checks available");
        }

        setStatus("Assessment Available", "collected");
    };

    try {
        const response = await fetch(API, {
            cache: "no-store"
        });

        if (!response.ok) {
            throw new Error(
                "Compliance API returned HTTP " + response.status
            );
        }

        const report = await response.json();
        render(report);

    } catch (error) {
        console.error("Compliance loading failed:", error);

        setStatus("Assessment Unavailable", "attention");

        showMessage(
            "Could not load the compliance report. " +
            "Verify that the dashboard server is running " +
            "and the compliance API is available."
        );
    }
});
