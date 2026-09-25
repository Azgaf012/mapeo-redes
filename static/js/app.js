document.addEventListener("DOMContentLoaded", () => {
    const start = document.getElementById("btn-start-scan");
    if (!start) return;

    const cidr = document.getElementById("scan-cidr");
    const gateway = document.getElementById("scan-gateway");
    const estimate = document.getElementById("scan-estimate");
    const version = document.getElementById("scan-snmp-version");
    const modal = new bootstrap.Modal(document.getElementById("scanProgressModal"),
                                      { backdrop: "static", keyboard: false });
    let estimateTimer;

    async function requestEstimate() {
        const response = await fetch(`/api/scan/estimate?cidr=${encodeURIComponent(cidr.value.trim())}`);
        const result = await response.json();
        if (!response.ok) throw new Error(result.error || "Rango no válido");
        return result;
    }

    async function updateEstimate() {
        try {
            const result = await requestEstimate();
            estimate.textContent = `${result.host_count} direcciones · duración orientativa: ${result.estimated_minutes} min. El límite configurado se aplica antes de iniciar.`;
            estimate.className = "small text-muted mt-2";
            start.disabled = false;
        } catch (error) {
            estimate.textContent = error.message;
            estimate.className = "small text-danger mt-2";
            start.disabled = true;
        }
    }

    cidr.addEventListener("input", () => {
        clearTimeout(estimateTimer);
        estimateTimer = setTimeout(updateEstimate, 300);
    });
    version.addEventListener("change", () => {
        const v3 = version.value === "3";
        document.getElementById("snmp-v3-fields").classList.toggle("d-none", !v3);
        document.getElementById("snmp-v2-fields").classList.toggle("d-none", v3);
    });

    function showError(message) {
        document.getElementById("scan-error-text").textContent = message;
        document.getElementById("scan-error-alert").classList.remove("d-none");
        const bar = document.getElementById("scan-progress-bar");
        bar.className = "progress-bar bg-danger";
        bar.textContent = "Error";
    }

    async function poll(jobId) {
        while (true) {
            await new Promise(resolve => setTimeout(resolve, 1500));
            try {
                const response = await fetch(`/api/scan/status/${jobId}`);
                const job = await response.json();
                if (!response.ok) throw new Error(job.error || "No se pudo leer el progreso");
                const bar = document.getElementById("scan-progress-bar");
                bar.style.width = `${job.progress}%`;
                bar.textContent = `${job.progress}%`;
                document.getElementById("scan-current-step").textContent = job.current_step || "Analizando…";
                document.getElementById("scan-discovered-count").textContent = job.discovered_count;
                if (job.status === "COMPLETED") {
                    bar.className = "progress-bar bg-success";
                    document.getElementById("scan-current-step").textContent = job.warnings
                        ? `Escaneo completado con avisos: ${job.warnings}`
                        : "Escaneo completado. Abriendo resumen…";
                    setTimeout(() => window.location.assign("/"), job.warnings ? 4000 : 1200);
                    return;
                }
                if (job.status === "FAILED") {
                    showError(job.error_message || "El escaneo falló");
                    return;
                }
            } catch (error) {
                showError(error.message);
                return;
            }
        }
    }

    start.addEventListener("click", async () => {
        try {
            await requestEstimate();
            const payload = {
                cidr: cidr.value.trim(), gateway: gateway.value.trim(),
                snmp_version: version.value,
                snmp_community: document.getElementById("scan-snmp").value,
                snmp_username: document.getElementById("scan-snmp-user").value,
                snmp_auth_protocol: document.getElementById("scan-snmp-auth-protocol").value,
                snmp_auth_key: document.getElementById("scan-snmp-auth").value,
                snmp_priv_key: document.getElementById("scan-snmp-priv").value,
            };
            document.getElementById("scan-error-alert").classList.add("d-none");
            modal.show();
            const response = await fetch("/api/scan/start", {
                method: "POST", headers: { "Content-Type": "application/json" },
                body: JSON.stringify(payload),
            });
            const result = await response.json();
            if (!response.ok) throw new Error(result.error || "No se pudo iniciar el escaneo");
            poll(result.job_id);
        } catch (error) {
            modal.show();
            showError(error.message);
        }
    });

    document.getElementById("btn-refresh-net").addEventListener("click", async () => {
        const response = await fetch("/api/network/detect");
        const network = await response.json();
        cidr.value = network.cidr;
        gateway.value = network.gateway || "";
        document.getElementById("net-ip").textContent = network.local_ip;
        document.getElementById("net-iface").textContent = network.interface;
        updateEstimate();
    });
    updateEstimate();
});
