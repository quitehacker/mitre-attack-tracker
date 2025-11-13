// MITRE ATT&CK Coverage Tracker - Main Application
class MITREAttackTracker {
    constructor() {
        this.attackData = null;
        this.mitreVersion = 'Loading...';
        this.techniques = [];
        this.tactics = [];
        this.detections = [];
        this.currentView = 'dashboard';
        this.editingDetectionId = null;

        this.init();
    }

    async init() {
        this.showLoading(true);
        await this.loadAttackData();
        this.loadUserData();
        this.setupEventListeners();
        this.renderCurrentView();
        this.showLoading(false);
    }

    showLoading(show) {
        const loader = document.getElementById('loadingIndicator');
        if (show) {
            loader.classList.remove('hidden');
        } else {
            loader.classList.add('hidden');
        }
    }

    async loadAttackData() {
        try {
            // Fetch MITRE ATT&CK Enterprise data from GitHub
            const response = await fetch('https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json');
            if (!response.ok) throw new Error('Failed to fetch MITRE data');

            this.attackData = await response.json();
            this.processAttackData();
        } catch (error) {
            console.error('Error loading MITRE ATT&CK data:', error);
            alert('Failed to load MITRE ATT&CK data. Please check your internet connection and refresh the page.');
        }
    }

    processAttackData() {
        if (!this.attackData || !this.attackData.objects) return;

        // Extract MITRE ATT&CK version number
        this.mitreVersionNumber = 'v?';
        this.mitreVersionDetails = '';

        // Look for x-mitre-collection object which contains version info
        const collectionObj = this.attackData.objects.find(obj => obj.type === 'x-mitre-collection');
        if (collectionObj) {
            // Extract version from x_mitre_version field
            if (collectionObj.x_mitre_version) {
                this.mitreVersionNumber = `v${collectionObj.x_mitre_version}`;
            }
            // Extract modified date
            if (collectionObj.modified) {
                const modifiedDate = new Date(collectionObj.modified);
                this.mitreVersionDetails = `Updated: ${modifiedDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`;
            }
        }

        // Fallback to identity object for date if collection not found
        if (!this.mitreVersionDetails) {
            const identityObj = this.attackData.objects.find(obj => obj.type === 'identity' && obj.name === 'The MITRE Corporation');
            if (identityObj && identityObj.created) {
                const createdDate = new Date(identityObj.created);
                this.mitreVersionDetails = `Created: ${createdDate.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' })}`;
            }
        }

        // Add STIX version
        if (this.attackData.spec_version) {
            this.mitreVersionDetails += ` | STIX ${this.attackData.spec_version}`;
        }

        // Keep the old mitreVersion for compatibility
        this.mitreVersion = `MITRE ATT&CK ${this.mitreVersionNumber}${this.mitreVersionDetails ? ' - ' + this.mitreVersionDetails : ''}`;

        // Extract tactics
        this.tactics = this.attackData.objects
            .filter(obj => obj.type === 'x-mitre-tactic')
            .map(tactic => ({
                id: tactic.id,
                name: tactic.name,
                shortName: tactic.x_mitre_shortname,
                description: tactic.description
            }))
            .sort((a, b) => a.name.localeCompare(b.name));

        // Extract techniques and sub-techniques
        this.techniques = this.attackData.objects
            .filter(obj => obj.type === 'attack-pattern' && !obj.revoked && !obj.deprecated)
            .map(tech => {
                const externalRefs = tech.external_references || [];
                const mitreRef = externalRefs.find(ref => ref.source_name === 'mitre-attack');
                const techniqueId = mitreRef ? mitreRef.external_id : '';
                const isSubTechnique = techniqueId.includes('.');
                const parentId = isSubTechnique ? techniqueId.split('.')[0] : null;

                // Extract tactics for this technique
                const killChainPhases = tech.kill_chain_phases || [];
                const techniqueTactics = killChainPhases
                    .filter(phase => phase.kill_chain_name === 'mitre-attack')
                    .map(phase => phase.phase_name);

                return {
                    id: techniqueId,
                    stixId: tech.id,
                    name: tech.name,
                    description: tech.description,
                    isSubTechnique: isSubTechnique,
                    parentId: parentId,
                    tactics: techniqueTactics,
                    platforms: tech.x_mitre_platforms || [],
                    url: mitreRef ? mitreRef.url : ''
                };
            })
            .filter(tech => tech.id) // Only include techniques with valid IDs
            .sort((a, b) => {
                // Sort by technique ID
                const aNum = parseFloat(a.id.substring(1).split('.')[0]);
                const bNum = parseFloat(b.id.substring(1).split('.')[0]);
                if (aNum !== bNum) return aNum - bNum;

                // If main technique is same, sort sub-techniques
                const aSubNum = a.id.includes('.') ? parseFloat(a.id.split('.')[1]) : 0;
                const bSubNum = b.id.includes('.') ? parseFloat(b.id.split('.')[1]) : 0;
                return aSubNum - bSubNum;
            });

        console.log(`Loaded ${this.techniques.length} techniques and ${this.tactics.length} tactics`);
    }

    loadUserData() {
        // Load detections from localStorage
        const savedDetections = localStorage.getItem('mitre_detections');
        if (savedDetections) {
            try {
                this.detections = JSON.parse(savedDetections);
            } catch (e) {
                console.error('Error parsing saved detections:', e);
                this.detections = [];
            }
        }
    }

    saveUserData() {
        localStorage.setItem('mitre_detections', JSON.stringify(this.detections));
    }

    setupEventListeners() {
        // Sidebar toggle
        document.getElementById('sidebarToggle').addEventListener('click', () => this.toggleSidebar());

        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => {
                const view = e.currentTarget.dataset.view;
                this.switchView(view);
            });
        });

        // Import/Export
        document.getElementById('exportBtn').addEventListener('click', () => this.exportData());
        document.getElementById('importBtn').addEventListener('click', () => {
            document.getElementById('fileInput').click();
        });
        document.getElementById('fileInput').addEventListener('change', (e) => this.importData(e));

        // Detection modal
        const modal = document.getElementById('detectionModal');
        document.getElementById('addDetectionBtn').addEventListener('click', () => {
            this.editingDetectionId = null;
            this.openDetectionModal();
        });

        modal.querySelector('.modal-close').addEventListener('click', () => this.closeDetectionModal());
        modal.querySelector('.modal-cancel').addEventListener('click', () => this.closeDetectionModal());

        document.getElementById('detectionForm').addEventListener('submit', (e) => {
            e.preventDefault();
            this.saveDetection();
        });

        // Click outside modal to close
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                this.closeDetectionModal();
            }
        });

        // Search and filters
        document.getElementById('techniqueSearch')?.addEventListener('input', () => this.renderTechniquesView());
        document.getElementById('tacticFilter')?.addEventListener('change', () => this.renderTechniquesView());
        document.getElementById('statusFilter')?.addEventListener('change', () => this.renderTechniquesView());
    }

    toggleSidebar() {
        const appContainer = document.querySelector('.app-container');
        const sidebar = document.getElementById('sidebar');

        if (window.innerWidth <= 768) {
            // Mobile: slide sidebar in/out
            sidebar.classList.toggle('mobile-open');
        } else {
            // Desktop: collapse/expand
            appContainer.classList.toggle('sidebar-collapsed');
        }
    }

    switchView(view) {
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.toggle('active', item.dataset.view === view);
        });

        // Update views
        document.querySelectorAll('.view').forEach(v => {
            v.classList.toggle('active', v.id === `${view}-view`);
        });

        this.currentView = view;
        this.renderCurrentView();

        // Close mobile sidebar after navigation
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.remove('mobile-open');
        }
    }

    renderCurrentView() {
        switch(this.currentView) {
            case 'dashboard':
                this.renderDashboard();
                break;
            case 'coverage':
                this.renderCoverageView();
                break;
            case 'techniques':
                this.renderTechniquesView();
                break;
            case 'detections':
                this.renderDetectionsView();
                break;
        }
    }

    // Calculate technique status and coverage
    getTechniqueStatus(technique) {
        const detectionRules = this.getDetectionRulesForTechnique(technique.id);
        return detectionRules > 0 ? 'detected' : 'not detected';
    }

    getDetectionRulesForTechnique(techniqueId) {
        return this.detections.filter(det =>
            det.isActive &&
            (det.technique1 === techniqueId ||
             det.technique2 === techniqueId ||
             det.technique3 === techniqueId)
        ).length;
    }

    calculateCoverage(technique) {
        const status = this.getTechniqueStatus(technique);
        return status === 'detected' ? 1.0 : 0.0;
    }

    // Dashboard rendering
    renderDashboard() {
        // Update MITRE version
        const versionNumberElement = document.getElementById('mitreVersionNumber');
        if (versionNumberElement) {
            versionNumberElement.textContent = this.mitreVersionNumber;
        }

        const versionDetailsElement = document.getElementById('mitreVersionDetails');
        if (versionDetailsElement) {
            versionDetailsElement.textContent = this.mitreVersionDetails;
        }

        // Update statistics
        document.getElementById('totalTechniques').textContent = this.techniques.length;
        document.getElementById('totalDetections').textContent =
            this.detections.filter(d => d.isActive).length;

        // Calculate overall coverage
        let totalCoverage = 0;
        let statusCounts = {
            detected: 0,
            'not detected': 0
        };

        this.techniques.forEach(tech => {
            const status = this.getTechniqueStatus(tech);
            statusCounts[status]++;
            totalCoverage += this.calculateCoverage(tech);
        });

        const overallCoveragePercent = ((totalCoverage / this.techniques.length) * 100).toFixed(1);
        document.getElementById('overallCoverage').textContent = `${overallCoveragePercent}%`;

        // Update status counts
        document.getElementById('detectedCount').textContent = statusCounts.detected;
        document.getElementById('noDetectionCount').textContent = statusCounts['not detected'];

        // Render spider chart
        this.renderSpiderChart();
    }

    renderSpiderChart() {
        const canvas = document.getElementById('spiderChart');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;
        const radius = Math.min(centerX, centerY) - 80;

        // Calculate coverage per tactic (in kill chain order)
        const killChainOrder = [
            'reconnaissance', 'resource-development', 'initial-access', 'execution',
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
            'discovery', 'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact'
        ];

        const tacticData = killChainOrder.map(shortName => {
            const tactic = this.tactics.find(t => t.shortName === shortName);
            if (!tactic) return null;

            const tacticTechniques = this.techniques.filter(tech =>
                tech.tactics.includes(shortName)
            );

            let totalCoverage = 0;
            tacticTechniques.forEach(tech => {
                totalCoverage += this.calculateCoverage(tech);
            });

            const coveragePercent = tacticTechniques.length > 0
                ? (totalCoverage / tacticTechniques.length) * 100
                : 0;

            return {
                name: tactic.name,
                coverage: coveragePercent
            };
        }).filter(t => t !== null);

        // Clear canvas
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Draw background circles
        ctx.strokeStyle = '#e9ecef';
        ctx.lineWidth = 1;
        for (let i = 1; i <= 5; i++) {
            ctx.beginPath();
            ctx.arc(centerX, centerY, (radius / 5) * i, 0, 2 * Math.PI);
            ctx.stroke();
        }

        // Draw axes
        const angleStep = (2 * Math.PI) / tacticData.length;
        tacticData.forEach((tactic, index) => {
            const angle = index * angleStep - Math.PI / 2;
            const x = centerX + radius * Math.cos(angle);
            const y = centerY + radius * Math.sin(angle);

            // Draw axis line
            ctx.beginPath();
            ctx.moveTo(centerX, centerY);
            ctx.lineTo(x, y);
            ctx.strokeStyle = '#dee2e6';
            ctx.lineWidth = 1;
            ctx.stroke();

            // Draw label
            const labelRadius = radius + 40;
            const labelX = centerX + labelRadius * Math.cos(angle);
            const labelY = centerY + labelRadius * Math.sin(angle);

            ctx.fillStyle = '#495057';
            ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto';
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';

            // Wrap text for long tactic names
            const words = tactic.name.split(' ');
            if (words.length > 2) {
                ctx.fillText(words.slice(0, 2).join(' '), labelX, labelY - 6);
                ctx.fillText(words.slice(2).join(' '), labelX, labelY + 6);
            } else {
                ctx.fillText(tactic.name, labelX, labelY);
            }
        });

        // Draw coverage polygon
        ctx.beginPath();
        tacticData.forEach((tactic, index) => {
            const angle = index * angleStep - Math.PI / 2;
            const distance = (tactic.coverage / 100) * radius;
            const x = centerX + distance * Math.cos(angle);
            const y = centerY + distance * Math.sin(angle);

            if (index === 0) {
                ctx.moveTo(x, y);
            } else {
                ctx.lineTo(x, y);
            }
        });
        ctx.closePath();

        // Fill polygon
        ctx.fillStyle = 'rgba(0, 102, 204, 0.2)';
        ctx.fill();

        // Stroke polygon
        ctx.strokeStyle = '#0066cc';
        ctx.lineWidth = 2;
        ctx.stroke();

        // Draw data points
        tacticData.forEach((tactic, index) => {
            const angle = index * angleStep - Math.PI / 2;
            const distance = (tactic.coverage / 100) * radius;
            const x = centerX + distance * Math.cos(angle);
            const y = centerY + distance * Math.sin(angle);

            ctx.beginPath();
            ctx.arc(x, y, 4, 0, 2 * Math.PI);
            ctx.fillStyle = '#0066cc';
            ctx.fill();
            ctx.strokeStyle = 'white';
            ctx.lineWidth = 2;
            ctx.stroke();
        });

        // Draw center point
        ctx.beginPath();
        ctx.arc(centerX, centerY, 3, 0, 2 * Math.PI);
        ctx.fillStyle = '#495057';
        ctx.fill();

        // Draw percentage labels on circles
        ctx.fillStyle = '#6c757d';
        ctx.font = '10px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto';
        ctx.textAlign = 'right';
        for (let i = 1; i <= 5; i++) {
            const percent = (i * 20);
            const y = centerY - (radius / 5) * i;
            ctx.fillText(`${percent}%`, centerX - 10, y);
        }
    }

    renderTacticCoverage() {
        const container = document.getElementById('tacticCoverage');
        if (!container) return;

        const tacticCoverageData = this.tactics.map(tactic => {
            const tacticTechniques = this.techniques.filter(tech =>
                tech.tactics.includes(tactic.shortName)
            );

            let totalCoverage = 0;
            tacticTechniques.forEach(tech => {
                totalCoverage += this.calculateCoverage(tech);
            });

            const coveragePercent = tacticTechniques.length > 0
                ? (totalCoverage / tacticTechniques.length) * 100
                : 0;

            return {
                name: tactic.name,
                coverage: coveragePercent,
                count: tacticTechniques.length
            };
        });

        container.innerHTML = tacticCoverageData.map(tactic => {
            const color = tactic.coverage >= 75 ? '#28a745' :
                         tactic.coverage >= 50 ? '#ffc107' :
                         tactic.coverage >= 25 ? '#fd7e14' : '#dc3545';

            return `
                <div class="tactic-card" style="border-left-color: ${color}">
                    <div class="tactic-card-name">${tactic.name}</div>
                    <div class="tactic-card-coverage" style="color: ${color}">
                        ${tactic.coverage.toFixed(1)}%
                    </div>
                    <div style="font-size: 0.85rem; color: #6c757d; margin-top: 0.25rem;">
                        ${tactic.count} techniques
                    </div>
                </div>
            `;
        }).join('');
    }

    // Coverage Matrix rendering
    renderCoverageView() {
        const container = document.getElementById('coverageMatrix');
        if (!container) return;

        // Kill chain order
        const killChainOrder = [
            'reconnaissance', 'resource-development', 'initial-access', 'execution',
            'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
            'discovery', 'lateral-movement', 'collection', 'command-and-control',
            'exfiltration', 'impact'
        ];

        // Group techniques by tactic in kill chain order
        const tacticGroups = killChainOrder.map(shortName => {
            const tactic = this.tactics.find(t => t.shortName === shortName);
            if (!tactic) return null;

            const techniques = this.techniques.filter(tech =>
                tech.tactics.includes(shortName) && !tech.isSubTechnique
            );

            return {
                tactic: tactic,
                techniques: techniques
            };
        }).filter(g => g !== null);

        // Calculate max techniques for table height
        const maxTechniques = Math.max(...tacticGroups.map(g => g.techniques.length), 1);

        let html = '<table class="matrix-table"><thead><tr>';

        // Header row with tactic names
        tacticGroups.forEach(group => {
            const tacticTechniques = group.techniques;
            let totalCoverage = 0;
            tacticTechniques.forEach(tech => {
                totalCoverage += this.calculateCoverage(tech);
            });
            const coveragePercent = tacticTechniques.length > 0
                ? ((totalCoverage / tacticTechniques.length) * 100).toFixed(0)
                : 0;

            html += `<th>
                <div style="font-weight: 600; margin-bottom: 0.25rem;">${group.tactic.name}</div>
                <div style="font-size: 0.75rem; font-weight: normal; color: #6c757d;">
                    ${coveragePercent}% (${tacticTechniques.length} techniques)
                </div>
            </th>`;
        });

        html += '</tr></thead><tbody>';

        // Data rows - one row per technique position
        for (let i = 0; i < maxTechniques; i++) {
            html += '<tr>';

            tacticGroups.forEach(group => {
                if (i < group.techniques.length) {
                    const tech = group.techniques[i];
                    const coverage = this.calculateCoverage(tech) * 100;
                    const status = this.getTechniqueStatus(tech);
                    const coverageClass = status === 'detected' ? 'coverage-high' : 'coverage-none';

                    html += `
                        <td class="coverage-cell ${coverageClass}" title="${tech.name}">
                            <a href="${tech.url}" target="_blank" class="technique-id">${tech.id}</a>
                            <div style="font-size: 0.7rem; margin-top: 0.25rem; color: inherit; font-weight: normal; max-width: 120px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                ${tech.name}
                            </div>
                        </td>
                    `;
                } else {
                    html += '<td class="coverage-cell coverage-none">-</td>';
                }
            });

            html += '</tr>';
        }

        html += '</tbody></table>';
        container.innerHTML = html;

        // Also render tactic coverage cards for the coverage view
        this.renderTacticCoverage();
    }

    // Techniques View
    renderTechniquesView() {
        const container = document.getElementById('techniquesTable');
        if (!container) return;

        // Populate tactic filter if empty
        const tacticFilter = document.getElementById('tacticFilter');
        if (tacticFilter && tacticFilter.options.length === 1) {
            this.tactics.forEach(tactic => {
                const option = document.createElement('option');
                option.value = tactic.shortName;
                option.textContent = tactic.name;
                tacticFilter.appendChild(option);
            });
        }

        // Apply filters
        const searchTerm = document.getElementById('techniqueSearch')?.value.toLowerCase() || '';
        const tacticFilterValue = document.getElementById('tacticFilter')?.value || '';
        const statusFilterValue = document.getElementById('statusFilter')?.value || '';

        let filteredTechniques = this.techniques.filter(tech => {
            // Search filter
            const matchesSearch = !searchTerm ||
                tech.id.toLowerCase().includes(searchTerm) ||
                tech.name.toLowerCase().includes(searchTerm);

            // Tactic filter
            const matchesTactic = !tacticFilterValue ||
                tech.tactics.includes(tacticFilterValue);

            // Status filter
            const status = this.getTechniqueStatus(tech);
            const matchesStatus = !statusFilterValue || status === statusFilterValue;

            return matchesSearch && matchesTactic && matchesStatus;
        });

        // Render table
        let html = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Tactics</th>
                        <th>Detection Rules</th>
                        <th>Coverage</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody>
        `;

        if (filteredTechniques.length === 0) {
            html += '<tr><td colspan="6" class="empty-state">No techniques found</td></tr>';
        } else {
            filteredTechniques.forEach(tech => {
                const status = this.getTechniqueStatus(tech);
                const coverage = (this.calculateCoverage(tech) * 100).toFixed(0);
                const detectionCount = this.getDetectionRulesForTechnique(tech.id);

                html += `
                    <tr>
                        <td>
                            <a href="${tech.url}" target="_blank" class="technique-id">${tech.id}</a>
                        </td>
                        <td>${tech.name}</td>
                        <td>${tech.tactics.join(', ')}</td>
                        <td>${detectionCount}</td>
                        <td>
                            <div style="display: flex; align-items: center; gap: 0.5rem;">
                                <div style="flex: 1; background: #e9ecef; height: 8px; border-radius: 4px; overflow: hidden;">
                                    <div style="width: ${coverage}%; height: 100%; background: ${
                                        coverage >= 75 ? '#28a745' :
                                        coverage >= 25 ? '#ffc107' : '#dc3545'
                                    };"></div>
                                </div>
                                <span style="min-width: 40px;">${coverage}%</span>
                            </div>
                        </td>
                        <td><span class="status-badge status-${status.replace(' ', '-')}">${status}</span></td>
                    </tr>
                `;
            });
        }

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    // Detections View
    renderDetectionsView() {
        const container = document.getElementById('detectionsTable');
        if (!container) return;

        // Populate technique datalist
        const datalist = document.getElementById('techniquesList');
        if (datalist && datalist.options.length === 0) {
            this.techniques.forEach(tech => {
                const option = document.createElement('option');
                option.value = tech.id;
                option.textContent = `${tech.id} - ${tech.name}`;
                datalist.appendChild(option);
            });
        }

        let html = `
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Name</th>
                        <th>Platform</th>
                        <th>Severity</th>
                        <th>Technique 1</th>
                        <th>Technique 2</th>
                        <th>Technique 3</th>
                        <th>Active</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
        `;

        if (this.detections.length === 0) {
            html += '<tr><td colspan="8" class="empty-state">No detection rules yet. Click "Add Detection Rule" to get started.</td></tr>';
        } else {
            this.detections.forEach(det => {
                html += `
                    <tr>
                        <td><strong>${det.name}</strong></td>
                        <td>${det.platform || '-'}</td>
                        <td>${det.severity || '-'}</td>
                        <td>${det.technique1 ? `<a href="${this.getTechniqueUrl(det.technique1)}" target="_blank" class="technique-id">${det.technique1}</a>` : '-'}</td>
                        <td>${det.technique2 ? `<a href="${this.getTechniqueUrl(det.technique2)}" target="_blank" class="technique-id">${det.technique2}</a>` : '-'}</td>
                        <td>${det.technique3 ? `<a href="${this.getTechniqueUrl(det.technique3)}" target="_blank" class="technique-id">${det.technique3}</a>` : '-'}</td>
                        <td>
                            <label class="toggle-switch">
                                <input type="checkbox" ${det.isActive ? 'checked' : ''}
                                    onchange="app.toggleDetectionActive('${det.id}')">
                                <span class="toggle-slider"></span>
                            </label>
                        </td>
                        <td>
                            <div class="action-buttons">
                                <button class="action-btn btn-edit" onclick="app.editDetection('${det.id}')" title="Edit">✏️</button>
                                <button class="action-btn btn-delete" onclick="app.deleteDetection('${det.id}')" title="Delete">🗑️</button>
                            </div>
                        </td>
                    </tr>
                `;
            });
        }

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    getTechniqueUrl(techniqueId) {
        const tech = this.techniques.find(t => t.id === techniqueId);
        return tech ? tech.url : `https://attack.mitre.org/techniques/${techniqueId.replace('.', '/')}`;
    }

    toggleDetectionActive(detectionId) {
        const detection = this.detections.find(d => d.id === detectionId);
        if (detection) {
            detection.isActive = !detection.isActive;
            this.saveUserData();
            this.renderCurrentView();
        }
    }

    editDetection(detectionId) {
        this.editingDetectionId = detectionId;
        const detection = this.detections.find(d => d.id === detectionId);
        if (detection) {
            document.getElementById('modalTitle').textContent = 'Edit Detection Rule';
            document.getElementById('detectionName').value = detection.name;
            document.getElementById('detectionDescription').value = detection.description || '';
            document.getElementById('detectionPlatform').value = detection.platform || '';
            document.getElementById('detectionSeverity').value = detection.severity || '';
            document.getElementById('detectionActive').checked = detection.isActive;
            document.getElementById('technique1').value = detection.technique1 || '';
            document.getElementById('technique2').value = detection.technique2 || '';
            document.getElementById('technique3').value = detection.technique3 || '';
            this.openDetectionModal();
        }
    }

    deleteDetection(detectionId) {
        if (confirm('Are you sure you want to delete this detection rule?')) {
            this.detections = this.detections.filter(d => d.id !== detectionId);
            this.saveUserData();
            this.renderCurrentView();
        }
    }

    openDetectionModal() {
        document.getElementById('detectionModal').classList.add('active');
        if (!this.editingDetectionId) {
            document.getElementById('modalTitle').textContent = 'Add Detection Rule';
            document.getElementById('detectionForm').reset();
        }
    }

    closeDetectionModal() {
        document.getElementById('detectionModal').classList.remove('active');
        document.getElementById('detectionForm').reset();
        this.editingDetectionId = null;
    }

    saveDetection() {
        const name = document.getElementById('detectionName').value.trim();
        const description = document.getElementById('detectionDescription').value.trim();
        const platform = document.getElementById('detectionPlatform').value;
        const severity = document.getElementById('detectionSeverity').value;
        const isActive = document.getElementById('detectionActive').checked;
        const technique1 = document.getElementById('technique1').value.trim().toUpperCase();
        const technique2 = document.getElementById('technique2').value.trim().toUpperCase();
        const technique3 = document.getElementById('technique3').value.trim().toUpperCase();

        if (!name) {
            alert('Please enter a detection name');
            return;
        }

        const detection = {
            id: this.editingDetectionId || this.generateId(),
            name,
            description,
            platform,
            severity,
            isActive,
            technique1,
            technique2,
            technique3,
            updatedAt: new Date().toISOString()
        };

        if (this.editingDetectionId) {
            const index = this.detections.findIndex(d => d.id === this.editingDetectionId);
            if (index !== -1) {
                this.detections[index] = detection;
            }
        } else {
            detection.createdAt = detection.updatedAt;
            this.detections.push(detection);
        }

        this.saveUserData();
        this.closeDetectionModal();
        this.renderCurrentView();
    }


    // Import/Export functionality
    exportData() {
        const data = {
            version: '3.0',
            exportDate: new Date().toISOString(),
            detections: this.detections
        };

        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `mitre-attack-coverage-${new Date().toISOString().split('T')[0]}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    importData(event) {
        const file = event.target.files[0];
        if (!file) return;

        const reader = new FileReader();
        reader.onload = (e) => {
            try {
                const data = JSON.parse(e.target.result);

                if (data.detections) {
                    this.detections = data.detections;
                }

                this.saveUserData();
                this.renderCurrentView();
                alert('Data imported successfully!');
            } catch (error) {
                console.error('Error importing data:', error);
                alert('Error importing data. Please check the file format.');
            }
        };
        reader.readAsText(file);

        // Reset file input
        event.target.value = '';
    }

    generateId() {
        return 'det_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    }
}

// Initialize the application
let app;
document.addEventListener('DOMContentLoaded', () => {
    app = new MITREAttackTracker();
});
