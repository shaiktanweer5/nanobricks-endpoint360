
/*
 * Nanobricks Endpoint360
 * Interactive Dashboard JavaScript v0.3.0
 *
 * Read-only dashboard for the latest saved Python assessment.
 * No external JavaScript libraries required.
 */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    const API_URL = "/api/latest-report";

    let currentReport = null;
    let installedApplications = [];
    let securityControls = [];

    const $ = (id) => document.getElementById(id);

    function object(value) {
        return value && typeof value === "object" &&
            !Array.isArray(value) ? value : {};
    }

    function array(value) {
        return Array.isArray(value) ? value : [];
    }

    function firstDefined(...values) {
        return values.find(
            (value) => value !== undefined && value !== null
        );
    }

    function display(value, fallback = "Not available") {
        if (value === undefined || value === null || value === "") {
            return fallback;
        }

        if (typeof value === "boolean") {
            return value ? "Yes" : "No";
        }

        if (typeof value === "object") {
            return fallback;
        }

        return String(value);
    }

    function setText(id, value, fallback = "Not available") {
        const element = $(id);

        if (element) {
            element.textContent = display(value, fallback);
        }
    }

    function makeElement(tag, className, content) {
        const element = document.createElement(tag);

        if (className) {
            element.className = className;
        }

        if (content !== undefined) {
            element.textContent = String(content);
        }

        return element;
    }

    function clear(element) {
        if (element) {
            element.replaceChildren();
        }
    }

    function emptyTable(id, columns, message) {
        const body = $(id);
        if (!body) return;

        clear(body);

        const row = document.createElement("tr");
        const cell = makeElement("td", "empty-row", message);

        cell.colSpan = columns;
        row.appendChild(cell);
        body.appendChild(row);
    }

    function addCell(row, value) {
        const cell = makeElement("td", "", display(value));
        row.appendChild(cell);
        return cell;
    }

    function addStatusCell(row, label, type) {
        const cell = document.createElement("td");
        const badge = makeElement(
            "span",
            `status ${type}`,
            label
        );

        cell.appendChild(badge);
        row.appendChild(cell);
        return cell;
    }

    function setBadge(id, label, type) {
        const element = $(id);
        if (!element) return;

        element.className = `status ${type}`;
        element.textContent = label;
    }

    function formatDate(value) {
        if (!value) return "Not available";

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return String(value);
        }

        return date.toLocaleString();
    }

    function getModule(report, name) {
        return object(object(report.Modules)[name]);
    }

    function getModuleData(report, name) {
        return object(getModule(report, name).Data);
    }

    function isCompleted(module) {
        return String(module.Status || "").toLowerCase() === "completed";
    }

    function getInstalledItems(data) {
        const source = object(data.InstalledSoftware);

        return array(firstDefined(
            source.Applications,
            source.Software,
            source.Items,
            source.Results,
            source.Packages,
            source.InstalledApplications,
            data.Applications
        ));
    }

    function getUpdateItems(data) {
        const source = object(data.AvailableUpdates);

        return array(firstDefined(
            source.Updates,
            source.Applications,
            source.Items,
            source.Results,
            source.Packages,
            data.Updates
        ));
    }

    function countFrom(source, items, ...names) {
        for (const name of names) {
            const value = source[name];

            if (
                value !== undefined &&
                value !== null &&
                value !== "" &&
                Number.isFinite(Number(value))
            ) {
                return Number(value);
            }
        }

        return items.length;
    }

    function getStatus(control) {
        const data = object(control.value);

        const raw = String(firstDefined(
            data.Status,
            data.CollectionStatus,
            data.AssessmentStatus,
            "Unknown"
        )).toLowerCase();

        if (
            raw.includes("denied") ||
            raw.includes("restricted") ||
            raw.includes("privilege")
        ) {
            return {
                label: "Restricted",
                type: "restricted",
                category: "restricted"
            };
        }

        if (
            raw === "collected" ||
            raw === "completed" ||
            raw === "success"
        ) {
            return {
                label: "Collected",
                type: "collected",
                category: "collected"
            };
        }

        if (
            raw === "failed" ||
            raw === "error"
        ) {
            return {
                label: "Collection Failed",
                type: "failed",
                category: "other"
            };
        }

        return {
            label: display(
                firstDefined(data.Status, data.CollectionStatus),
                "Unknown"
            ),
            type: "unknown",
            category: "other"
        };
    }

    function normalizeSecurity(data) {
        const security = object(data.Security);

        return Object.entries(security).map(([name, value]) => ({
            name,
            value,
            status: getStatus({ value })
        }));
    }

    function humanName(name) {
        return String(name)
            .replace(/([a-z])([A-Z])/g, "$1 $2")
            .replace(/([A-Z])([A-Z][a-z])/g, "$1 $2");
    }

    function makeDonut(id, segments, centerValue, centerLabel) {
        const container = $(id);
        if (!container) return;

        clear(container);

        const total = segments.reduce(
            (sum, segment) => sum + segment.value,
            0
        );

        if (total === 0) {
            container.appendChild(
                makeElement(
                    "p",
                    "chart-empty",
                    "No assessed results available"
                )
            );
            return;
        }

        const layout = makeElement("div", "chart-layout");
        const donut = makeElement("div", "donut");
        const center = makeElement("div", "donut-center");

        center.appendChild(
            makeElement("strong", "", centerValue)
        );

        center.appendChild(
            makeElement("span", "", centerLabel)
        );

        donut.appendChild(center);

        let position = 0;
        const stops = [];

        segments.forEach((segment) => {
            const start = position;
            position += (segment.value / total) * 100;

            stops.push(
                `${segment.color} ${start}% ${position}%`
            );
        });

        donut.style.background =
            `conic-gradient(${stops.join(", ")})`;

        donut.setAttribute(
            "role",
            "img"
        );

        donut.setAttribute(
            "aria-label",
            segments.map(
                (item) => `${item.label}: ${item.value}`
            ).join(", ")
        );

        const legend = makeElement("div", "chart-legend");

        segments.forEach((segment) => {
            const row = makeElement("div", "legend-row");
            const dot = makeElement("span", "legend-dot");

            dot.style.background = segment.color;

            row.appendChild(dot);
            row.appendChild(
                makeElement("span", "", segment.label)
            );
            row.appendChild(
                makeElement("strong", "", segment.value)
            );

            legend.appendChild(row);
        });

        layout.appendChild(donut);
        layout.appendChild(legend);
        container.appendChild(layout);
    }

    function renderOverview(report) {
        const summary = object(report.Summary);
        const modules = object(report.Modules);

        const total = Number(
            firstDefined(
                summary.TotalModules,
                Object.keys(modules).length
            )
        );

        const completed = Number(
            firstDefined(
                summary.CompletedModules,
                Object.values(modules).filter(isCompleted).length
            )
        );

        const failed = Number(
            firstDefined(summary.FailedModules, total - completed)
        );

        const softwareModule = getModule(report, "Software Assessment");
        const software = getModuleData(report, "Software Assessment");

        const installed = object(software.InstalledSoftware);
        const updates = object(software.AvailableUpdates);

        const appItems = getInstalledItems(software);
        const updateItems = getUpdateItems(software);

        const securityModule = getModule(report, "Windows Security");

        setText("module-count", `${completed} / ${total}`);

        setText(
            "application-count",
            isCompleted(softwareModule)
                ? countFrom(installed, appItems, "Count", "TotalCount")
                : "--"
        );

        setText(
            "update-count",
            isCompleted(softwareModule)
                ? countFrom(updates, updateItems, "Count", "TotalCount")
                : "--"
        );

        const restricted = securityControls.filter(
            (control) => control.status.category === "restricted"
        ).length;

        setText(
            "restricted-count",
            isCompleted(securityModule) ? restricted : "--"
        );

        makeDonut(
            "module-chart",
            [
                {
                    label: "Completed",
                    value: completed,
                    color: "#2fa93a"
                },
                {
                    label: "Failed",
                    value: failed,
                    color: "#d94c53"
                },
                {
                    label: "Other",
                    value: Math.max(0, total - completed - failed),
                    color: "#a2adb0"
                }
            ],
            `${completed}/${total}`,
            "Modules"
        );

        const collected = securityControls.filter(
            (control) => control.status.category === "collected"
        ).length;

        const other = securityControls.length - collected - restricted;

        makeDonut(
            "security-chart",
            [
                {
                    label: "Collected",
                    value: collected,
                    color: "#2fa93a"
                },
                {
                    label: "Restricted",
                    value: restricted,
                    color: "#e4a315"
                },
                {
                    label: "Other / Unknown",
                    value: other,
                    color: "#a2adb0"
                }
            ],
            securityControls.length,
            "Checks"
        );
    }

    function renderDevice(report) {
        const module = getModule(report, "System Inventory");
        const data = getModuleData(report, "System Inventory");

        if (!isCompleted(module)) {
            [
                "computer-name",
                "operating-system",
                "processor",
                "ram",
                "drive-count",
                "assessment-time"
            ].forEach((id) => setText(id, "Not assessed"));

            emptyTable(
                "storage-table-body",
                4,
                "System inventory was not completed"
            );
            return;
        }

        const os = object(data.OperatingSystem);
        const hardware = object(data.Hardware);
        const storage = array(data.Storage);

        setText(
            "computer-name",
            firstDefined(data.ComputerName, report.ComputerName)
        );

        setText(
            "operating-system",
            firstDefined(os.Caption, os.Name, os.Version)
        );

        setText(
            "processor",
            firstDefined(hardware.Processor, hardware.CPU)
        );

        const ram = firstDefined(
            hardware.RAM_GB,
            hardware.RamGB,
            hardware.MemoryGB
        );

        setText(
            "ram",
            ram === undefined ? undefined : `${ram} GB`
        );

        setText("drive-count", storage.length);

        setText(
            "assessment-time",
            formatDate(
                firstDefined(
                    report.AssessmentCompleted,
                    data.AssessmentTimeUTC
                )
            )
        );

        const body = $("storage-table-body");
        if (!body) return;

        clear(body);

        if (!storage.length) {
            emptyTable(
                "storage-table-body",
                4,
                "No storage records available"
            );
            return;
        }

        storage.forEach((drive) => {
            const row = document.createElement("tr");

            addCell(
                row,
                firstDefined(
                    drive.Drive,
                    drive.DeviceID,
                    drive.Name
                )
            );

            const total = firstDefined(
                drive.Total_GB,
                drive.TotalGB,
                drive.SizeGB
            );

            const used = firstDefined(
                drive.Used_GB,
                drive.UsedGB
            );

            const free = firstDefined(
                drive.Free_GB,
                drive.FreeGB
            );

            addCell(
                row,
                total === undefined ? "Unknown" : `${total} GB`
            );

            addCell(
                row,
                used === undefined ? "Unknown" : `${used} GB`
            );

            addCell(
                row,
                free === undefined ? "Unknown" : `${free} GB`
            );

            body.appendChild(row);
        });
    }

    function renderSecurity() {
        const filter = $("security-filter");
        const selected = filter ? filter.value : "all";

        const visible = securityControls.filter((control) => {
            return selected === "all" ||
                control.status.category === selected;
        });

        const body = $("security-table-body");
        if (!body) return;

        clear(body);

        if (!visible.length) {
            emptyTable(
                "security-table-body",
                3,
                securityControls.length
                    ? "No security checks match this filter"
                    : "No security assessment data available"
            );
            return;
        }

        visible.forEach((control) => {
            const row = document.createElement("tr");

            addCell(row, humanName(control.name));

            addStatusCell(
                row,
                control.status.label,
                control.status.type
            );

            const cell = document.createElement("td");
            const details = document.createElement("details");
            const summary = makeElement(
                "summary",
                "",
                "View collected evidence"
            );

            const pre = makeElement(
                "pre",
                "",
                JSON.stringify(control.value, null, 2)
            );

            details.appendChild(summary);
            details.appendChild(pre);
            cell.appendChild(details);
            row.appendChild(cell);

            body.appendChild(row);
        });
    }

    function renderSoftware() {
        const input = $("software-search");

        const query = input
            ? input.value.trim().toLowerCase()
            : "";

        const visible = installedApplications.filter((app) => {
            const searchText = [
                app.Name,
                app.Version,
                app.Publisher
            ].map((value) => display(value, "")).join(" ").toLowerCase();

            return searchText.includes(query);
        });

        const body = $("software-table-body");
        if (!body) return;

        clear(body);

        if (!visible.length) {
            emptyTable(
                "software-table-body",
                3,
                installedApplications.length
                    ? "No applications match your search"
                    : "No installed application records available"
            );
            return;
        }

        visible
            .slice()
            .sort((a, b) =>
                display(a.Name, "").localeCompare(
                    display(b.Name, "")
                )
            )
            .forEach((app) => {
                const row = document.createElement("tr");

                addCell(row, app.Name);
                addCell(row, app.Version);
                addCell(row, app.Publisher);

                body.appendChild(row);
            });
    }

    function renderUpdates(report) {
        const module = getModule(report, "Software Assessment");
        const data = getModuleData(report, "Software Assessment");
        const updates = getUpdateItems(data);

        const body = $("updates-table-body");
        if (!body) return;

        clear(body);

        if (!isCompleted(module)) {
            emptyTable(
                "updates-table-body",
                4,
                "Software update assessment was not completed"
            );
            return;
        }

        if (!updates.length) {
            emptyTable(
                "updates-table-body",
                4,
                "No update records returned by the assessment"
            );
            return;
        }

        updates.forEach((update) => {
            const row = document.createElement("tr");

            addCell(
                row,
                firstDefined(
                    update.Name,
                    update.Application,
                    update.PackageName
                )
            );

            addCell(
                row,
                firstDefined(
                    update.InstalledVersion,
                    update.Version,
                    update.CurrentVersion
                )
            );

            addCell(
                row,
                firstDefined(
                    update.AvailableVersion,
                    update.LatestVersion,
                    update.NewVersion
                )
            );

            addStatusCell(
                row,
                "Review Update",
                "attention"
            );

            body.appendChild(row);
        });
    }

    function addRecommendation(title, description, status) {
        const list = $("recommendations-list");
        if (!list) return;

        const item = makeElement("article", "recommendation");
        const icon = makeElement(
            "div",
            "recommendation-icon",
            "!"
        );

        const content = document.createElement("div");

        content.appendChild(
            makeElement("h4", "", title)
        );

        content.appendChild(
            makeElement("p", "", description)
        );

        content.appendChild(
            makeElement(
                "span",
                `status ${status}`,
                status === "restricted"
                    ? "Verification Required"
                    : "Review Recommended"
            )
        );

        item.appendChild(icon);
        item.appendChild(content);
        list.appendChild(item);
    }

    function renderRecommendations(report) {
        const list = $("recommendations-list");
        if (!list) return;

        clear(list);

        const restricted = securityControls.filter(
            (control) => control.status.category === "restricted"
        );

        restricted.forEach((control) => {
            addRecommendation(
                `Verify ${humanName(control.name)}`,
                "The assessment could not verify this security control. " +
                "Review the collection error and rerun with approved " +
                "administrator privileges if appropriate.",
                "restricted"
            );
        });

        const softwareModule = getModule(
            report,
            "Software Assessment"
        );

        const software = getModuleData(
            report,
            "Software Assessment"
        );

        const updates = object(software.AvailableUpdates);

        const updateCount = countFrom(
            updates,
            getUpdateItems(software),
            "Count",
            "TotalCount"
        );

        if (isCompleted(softwareModule) && updateCount > 0) {
            addRecommendation(
                `Review ${updateCount} available software update(s)`,
                "Confirm application compatibility and verify the " +
                "publisher or trusted package source before updating. " +
                "Endpoint360 has not installed any updates.",
                "attention"
            );
        }

        const failed = securityControls.filter(
            (control) => control.status.type === "failed"
        );

        failed.forEach((control) => {
            addRecommendation(
                `Investigate ${humanName(control.name)} collection`,
                "This check returned a collection failure. " +
                "Investigate the error before making a security decision.",
                "attention"
            );
        });

        if (!list.children.length) {
            list.appendChild(
                makeElement(
                    "p",
                    "small-label",
                    "No follow-up recommendations were generated " +
                    "from the currently supported assessment checks. " +
                    "This does not establish compliance."
                )
            );
        }
    }

    function downloadJSON() {
        if (!currentReport) return;

        const content = JSON.stringify(
            currentReport,
            null,
            2
        );

        const blob = new Blob(
            [content],
            { type: "application/json" }
        );

        const url = URL.createObjectURL(blob);
        const link = document.createElement("a");

        const computer = String(
            currentReport.ComputerName || "Endpoint"
        ).replace(/[^a-zA-Z0-9_-]/g, "_");

        link.href = url;
        link.download = `${computer}-Endpoint360-Assessment.json`;

        document.body.appendChild(link);
        link.click();
        link.remove();

        setTimeout(() => URL.revokeObjectURL(url), 1000);
    }

    function setupNavigation() {
        const links = Array.from(
            document.querySelectorAll(
                ".sidebar-nav .nav-item"
            )
        );

        function setActive(id) {
            links.forEach((link) => {
                const active = link.getAttribute("href") === `#${id}`;

                link.classList.toggle("active", active);

                if (active) {
                    link.setAttribute("aria-current", "location");
                } else {
                    link.removeAttribute("aria-current");
                }
            });
        }

        links.forEach((link) => {
            link.addEventListener("click", () => {
                const id = link.getAttribute("href").slice(1);
                setActive(id);
            });
        });

        const sections = Array.from(
            document.querySelectorAll(".dashboard-section")
        );

        if ("IntersectionObserver" in window) {
            const observer = new IntersectionObserver(
                (entries) => {
                    const visible = entries
                        .filter((entry) => entry.isIntersecting)
                        .sort(
                            (a, b) =>
                                b.intersectionRatio -
                                a.intersectionRatio
                        );

                    if (visible.length) {
                        setActive(visible[0].target.id);
                    }
                },
                {
                    rootMargin: "-10% 0px -55% 0px",
                    threshold: [0, 0.1, 0.25, 0.5]
                }
            );

            sections.forEach((section) => {
                observer.observe(section);
            });
        }

        const initial = window.location.hash.slice(1);

        if (initial && $(initial)) {
            setActive(initial);
        }
    }

    function setupInteractions() {
        const securityFilter = $("security-filter");

        if (securityFilter) {
            securityFilter.addEventListener(
                "change",
                renderSecurity
            );
        }

        const softwareSearch = $("software-search");

        if (softwareSearch) {
            softwareSearch.addEventListener(
                "input",
                renderSoftware
            );
        }

        const download = $("download-json");

        if (download) {
            download.addEventListener(
                "click",
                downloadJSON
            );
        }
    }

    async function loadAssessment() {
        setBadge(
            "data-status",
            "Loading assessment...",
            "attention"
        );

        try {
            const response = await fetch(
                API_URL,
                { cache: "no-store" }
            );

            if (!response.ok) {
                throw new Error(
                    `Assessment API returned HTTP ${response.status}`
                );
            }

            const report = await response.json();

            if (
                !report ||
                typeof report !== "object" ||
                !report.Modules ||
                !report.Summary
            ) {
                throw new Error(
                    "The assessment report has an unexpected structure"
                );
            }

            currentReport = report;

            const securityModule = getModule(
                report,
                "Windows Security"
            );

            const security = getModuleData(
                report,
                "Windows Security"
            );

            securityControls = isCompleted(securityModule)
                ? normalizeSecurity(security)
                : [];

            const softwareModule = getModule(
                report,
                "Software Assessment"
            );

            const software = getModuleData(
                report,
                "Software Assessment"
            );

            installedApplications = isCompleted(softwareModule)
                ? getInstalledItems(software)
                : [];

            renderOverview(report);
            renderDevice(report);
            renderSecurity();
            renderSoftware();
            renderUpdates(report);
            renderRecommendations(report);

            setBadge(
                "data-status",
                "Latest saved assessment loaded",
                "collected"
            );

            setBadge(
                "report-status",
                "Report Available",
                "collected"
            );

            const download = $("download-json");

            if (download) {
                download.disabled = false;
            }

            console.info(
                "Nanobricks Endpoint360",
                "Assessment loaded:",
                report.ComputerName
            );

        } catch (error) {
            console.error(
                "Endpoint360 report loading failed:",
                error
            );

            setBadge(
                "data-status",
                "Assessment unavailable",
                "failed"
            );

            setBadge(
                "report-status",
                "Report unavailable",
                "failed"
            );

            const message =
                "Could not load the latest saved assessment. " +
                "Check that the Python dashboard server is running.";

            ["module-chart", "security-chart"].forEach((id) => {
                const container = $(id);

                if (container) {
                    clear(container);
                    container.appendChild(
                        makeElement("p", "chart-empty", message)
                    );
                }
            });

            emptyTable("storage-table-body", 4, message);
            emptyTable("security-table-body", 3, message);
            emptyTable("software-table-body", 3, message);
            emptyTable("updates-table-body", 4, message);
        }
    }

    setupNavigation();
    setupInteractions();
    loadAssessment();
});
