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

        // Extract MITRE ATT&CK version
        const identityObj = this.attackData.objects.find(obj => obj.type === 'identity' && obj.name === 'The MITRE Corporation');
        if (identityObj && identityObj.created) {
            const createdDate = new Date(identityObj.created);
            this.mitreVersion = `MITRE ATT&CK (Updated: ${createdDate.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })})`;
        }

        // Try to extract spec version if available
        if (this.attackData.spec_version) {
            this.mitreVersion += ` | STIX ${this.attackData.spec_version}`;
        }

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
        // Navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => {
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

    switchView(view) {
        // Update navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.toggle('active', tab.dataset.view === view);
        });

        // Update views
        document.querySelectorAll('.view').forEach(v => {
            v.classList.toggle('active', v.id === `${view}-view`);
        });

        this.currentView = view;
        this.renderCurrentView();
    }

    renderCurrentView() {
        switch(this.currentView) {
            case 'dashboard':
                this.renderDashboard();
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
        const versionElement = document.getElementById('mitreVersion');
        if (versionElement) {
            versionElement.textContent = this.mitreVersion;
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

        // Render tactic coverage
        this.renderTacticCoverage();
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

        // Group techniques by tactic
        const tacticTechniques = {};
        this.tactics.forEach(tactic => {
            tacticTechniques[tactic.name] = this.techniques.filter(tech =>
                tech.tactics.includes(tactic.shortName) && !tech.isSubTechnique
            );
        });

        let html = '<table class="matrix-table"><thead><tr><th>Tactic</th>';

        // Get max techniques per tactic for column count
        const maxTechniques = Math.max(...Object.values(tacticTechniques).map(t => t.length), 10);

        for (let i = 1; i <= Math.min(maxTechniques, 10); i++) {
            html += `<th>T${i}</th>`;
        }
        html += '</tr></thead><tbody>';

        this.tactics.forEach(tactic => {
            const techniques = tacticTechniques[tactic.name] || [];
            html += `<tr><td><strong>${tactic.name}</strong></td>`;

            for (let i = 0; i < Math.min(maxTechniques, 10); i++) {
                if (i < techniques.length) {
                    const tech = techniques[i];
                    const coverage = this.calculateCoverage(tech) * 100;
                    const coverageClass = coverage >= 75 ? 'coverage-high' :
                                        coverage >= 25 ? 'coverage-medium' :
                                        coverage > 0 ? 'coverage-low' : 'coverage-none';

                    html += `
                        <td class="coverage-cell ${coverageClass}" title="${tech.name}">
                            <a href="${tech.url}" target="_blank" class="technique-id">${tech.id}</a>
                        </td>
                    `;
                } else {
                    html += '<td class="coverage-cell coverage-none">-</td>';
                }
            }
            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
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
