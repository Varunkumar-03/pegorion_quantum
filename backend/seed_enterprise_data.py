"""Enterprise seed script for Pegorion Platform.

Populates realistic Vertical Bridge telecommunications infrastructure data across:
1. Landlords and Ground Leases
2. Lease Obligations and Deadlines
3. Legal Matters, Parties, and Case Events
4. Contracts, Clauses, and Playbooks
5. Operations Workflows, Runs, Tasks, and Approvals
6. Initial Evidence Vault Audit Entries
"""

import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.core.database import SessionLocal
from app.models.infrastructure import Property, TowerSite
from app.models.property_lease import Landlord, Lease, Obligation
from app.models.legal import LegalMatter, MatterParty, CaseEvent, LegalSource
from app.models.operations import Workflow, WorkflowRun, Task, Approval
from app.models.contracts import Contract, Clause, Playbook, PlaybookRule
from app.security_pqc.audit_vault import evidence_vault_service


def seed_enterprise():
    db = SessionLocal()
    org_id = "org-vb-default"

    try:
        # Retrieve existing properties
        props = db.query(Property).all()
        prop_map = {p.city: p.id for p in props}
        prop_ids = [p.id for p in props]

        default_prop_id = prop_ids[0] if prop_ids else "prop-default-01"

        print("1. Seeding Landlords...")
        landlords_data = [
            {"id": "ll-001", "name": "TowerCo Properties LLC", "address": "100 Crescent Ct, Dallas, TX", "contact_person": "Robert Vance", "email": "rvance@towercoprop.com", "phone": "214-555-0192"},
            {"id": "ll-002", "name": "MetroTowers Realty Group", "address": "1200 Smith St, Houston, TX", "contact_person": "Elena Morales", "email": "emorales@metrotowers.com", "phone": "713-555-0144"},
            {"id": "ll-003", "name": "American Land & Infrastructure Trust", "address": "500 W 2nd St, Austin, TX", "contact_person": "Marcus Sterling", "email": "msterling@alitrust.com", "phone": "512-555-0188"},
            {"id": "ll-004", "name": "Sunshine Wireless Realty LLC", "address": "801 Brickell Ave, Miami, FL", "contact_person": "Sophia Alvarez", "email": "salvarez@sunshinewireless.com", "phone": "305-555-0112"},
            {"id": "ll-005", "name": "Peach State Tower Holdings", "address": "3344 Peachtree Rd, Atlanta, GA", "contact_person": "David Kim", "email": "dkim@peachstatetowers.com", "phone": "404-555-0176"}
        ]

        db.query(Landlord).delete()
        for ld in landlords_data:
            db.add(Landlord(**ld))
        db.commit()

        print("2. Seeding Leases...")
        db.query(Obligation).delete()
        db.query(Lease).delete()

        now = datetime.utcnow()
        leases_data = [
            {
                "id": "lease-001-dallas",
                "property_id": prop_map.get("Dallas", default_prop_id),
                "landlord_id": "ll-001",
                "lease_number": "VB-LEASE-2024-001",
                "term_months": 120,
                "start_date": now - timedelta(days=365),
                "end_date": now + timedelta(days=3285),  # ~9 years remaining
                "annual_rent": 480000.0,
                "rent_escalation_pct": 2.5,
                "status": "active",
                "organization_id": org_id
            },
            {
                "id": "lease-002-houston",
                "property_id": prop_map.get("Houston", default_prop_id),
                "landlord_id": "ll-002",
                "lease_number": "VB-LEASE-2024-002",
                "term_months": 120,
                "start_date": now - timedelta(days=730),
                "end_date": now + timedelta(days=120),  # Expiring soon (<180 days)
                "annual_rent": 350000.0,
                "rent_escalation_pct": 3.0,
                "status": "active",
                "organization_id": org_id
            },
            {
                "id": "lease-003-austin",
                "property_id": prop_map.get("Austin", default_prop_id),
                "landlord_id": "ll-003",
                "lease_number": "VB-LEASE-2024-003",
                "term_months": 180,
                "start_date": now - timedelta(days=100),
                "end_date": now + timedelta(days=5375),
                "annual_rent": 420000.0,
                "rent_escalation_pct": 2.75,
                "status": "active",
                "organization_id": org_id
            },
            {
                "id": "lease-004-miami",
                "property_id": prop_map.get("Miami", default_prop_id),
                "landlord_id": "ll-004",
                "lease_number": "VB-LEASE-2024-004",
                "term_months": 120,
                "start_date": now - timedelta(days=500),
                "end_date": now + timedelta(days=3150),
                "annual_rent": 540000.0,
                "rent_escalation_pct": 3.2,
                "status": "active",
                "organization_id": org_id
            },
            {
                "id": "lease-005-atlanta",
                "property_id": prop_map.get("Atlanta", default_prop_id),
                "landlord_id": "ll-005",
                "lease_number": "VB-LEASE-2024-005",
                "term_months": 120,
                "start_date": now - timedelta(days=600),
                "end_date": now + timedelta(days=3050),
                "annual_rent": 390000.0,
                "rent_escalation_pct": 2.5,
                "status": "active",
                "organization_id": org_id
            }
        ]

        for ld in leases_data:
            db.add(Lease(**ld))
        db.commit()

        print("3. Seeding Lease Obligations...")
        obligations_data = [
            {"id": "ob-001", "lease_id": "lease-001-dallas", "description": "Serve written notification of intent to exercise 5-year extension option at least 180 days prior to expiration.", "obligation_type": "Critical Renewal", "due_date": now + timedelta(days=3105), "is_met": False},
            {"id": "ob-002", "lease_id": "lease-001-dallas", "description": "Calculate and apply 2.5% annual CPI rent increase to landlord monthly payment schedule.", "obligation_type": "Financial", "due_date": now + timedelta(days=45), "is_met": False},
            {"id": "ob-003", "lease_id": "lease-001-dallas", "description": "Deliver annual ACORD 25 Certificate of Liability Insurance ($2,000,000) naming Lessor as additional insured.", "obligation_type": "Insurance Covenant", "due_date": now + timedelta(days=90), "is_met": True},
            {"id": "ob-004", "lease_id": "lease-002-houston", "description": "Execute preliminary 180-day option renewal notice window for Houston Central Ground Site.", "obligation_type": "Critical Renewal", "due_date": now + timedelta(days=30), "is_met": False},
            {"id": "ob-005", "lease_id": "lease-002-houston", "description": "Environmental Phase I ESA recertification for compound soil boundary.", "obligation_type": "Compliance", "due_date": now + timedelta(days=60), "is_met": False},
            {"id": "ob-006", "lease_id": "lease-003-austin", "description": "Austin Ridge compound vegetation control and perimeter security audit.", "obligation_type": "Maintenance", "due_date": now + timedelta(days=15), "is_met": False},
            {"id": "ob-007", "lease_id": "lease-004-miami", "description": "Hurricane season structural tie-down and backup diesel generator capacity test.", "obligation_type": "Operational", "due_date": now + timedelta(days=75), "is_met": True}
        ]

        for ob in obligations_data:
            db.add(Obligation(**ob))
        db.commit()

        print("4. Seeding Legal Matters, Parties & Events...")
        db.query(CaseEvent).delete()
        db.query(MatterParty).delete()
        db.query(LegalMatter).delete()

        matters_data = [
            {
                "id": "matter-101",
                "matter_number": "VB-LEGAL-2024-101",
                "title": "Lease Risk Review & Asymmetrical Cure Defense - Dallas Site Alpha",
                "matter_type": "Contract Review",
                "status": "open",
                "priority": "high",
                "organization_id": org_id,
                "opened_date": now - timedelta(days=30)
            },
            {
                "id": "matter-102",
                "matter_number": "VB-LEGAL-2024-102",
                "title": "FAA Part 77 Obstruction Evaluation & Strobe Lighting Compliance",
                "matter_type": "compliance",
                "status": "open",
                "priority": "high",
                "organization_id": org_id,
                "opened_date": now - timedelta(days=45)
            },
            {
                "id": "matter-103",
                "matter_number": "VB-LEGAL-2024-103",
                "title": "Houston Central Landlord Unilateral Default & Escalation Dispute",
                "matter_type": "litigation",
                "status": "open",
                "priority": "critical",
                "organization_id": org_id,
                "opened_date": now - timedelta(days=15)
            },
            {
                "id": "matter-104",
                "matter_number": "VB-LEGAL-2024-104",
                "title": "Carrier 5G Massive MIMO Sublease Consent Waiver Agreement",
                "matter_type": "contract_negotiation",
                "status": "open",
                "priority": "medium",
                "organization_id": org_id,
                "opened_date": now - timedelta(days=10)
            },
            {
                "id": "matter-105",
                "matter_number": "VB-LEGAL-2024-105",
                "title": "Municipal Zoning Setback Variance for Austin Ridge Tower Expansion",
                "matter_type": "regulatory",
                "status": "pending_hearing",
                "priority": "medium",
                "organization_id": org_id,
                "opened_date": now - timedelta(days=60)
            }
        ]

        for m in matters_data:
            db.add(LegalMatter(**m))
        db.commit()

        events_data = [
            {"id": "evt-m-01", "matter_id": "matter-101", "event_type": "filing", "title": "AI Risk Audit Memorandum Filed", "description": "Identified 15-day cure period exposure and uncapped CPI escalation.", "event_date": now - timedelta(days=25)},
            {"id": "evt-m-02", "matter_id": "matter-101", "event_type": "negotiation", "title": "Draft Amendment Served on Landlord Counsel", "description": "Proposed 30-day bilateral cure period and 3.0% annual CPI cap.", "event_date": now - timedelta(days=10)},
            {"id": "evt-m-03", "matter_id": "matter-102", "event_type": "regulatory_submission", "title": "FAA Form 7460-1 Notice of Proposed Construction Submitted", "description": "Submitted for microwave dish elevation increase to 185ft AGL.", "event_date": now - timedelta(days=40)},
            {"id": "evt-m-04", "matter_id": "matter-103", "event_type": "demand_letter", "title": "Landlord Notice of Dispute Received", "description": "Landlord contested holdover penalty calculation.", "event_date": now - timedelta(days=14)}
        ]
        for ev in events_data:
            db.add(CaseEvent(**ev))
        db.commit()

        print("5. Seeding Contracts & Playbooks...")
        db.query(Clause).delete()
        db.query(Contract).delete()
        db.query(PlaybookRule).delete()
        db.query(Playbook).delete()

        pb = Playbook(
            id="pb-001",
            name="Vertical Bridge Master Telecom Ground Lease Playbook",
            description="Institutional guidelines for reviewing telecommunications tower ground leases and carrier agreements.",
            domain="lease_review"
        )
        db.add(pb)
        db.commit()

        rules = [
            PlaybookRule(id="pbr-01", playbook_id="pb-001", rule_name="Default Cure Period Minimum", description="Default cure period must be at least 30 business days with notice.", condition="cure_period < 30", action="reject_and_request_30_days"),
            PlaybookRule(id="pbr-02", playbook_id="pb-001", rule_name="Annual CPI Escalation Cap", description="Annual rent increase must not exceed 3.5% maximum ceiling.", condition="cpi_cap > 3.5 or cpi_uncapped", action="require_ceiling_cap"),
            PlaybookRule(id="pbr-03", playbook_id="pb-001", rule_name="Carrier Affiliate Subletting Freedom", description="Unrestricted assignment to Tier 1 wireless carriers (Verizon, AT&T, T-Mobile) without landlord consent.", condition="landlord_consent_required_for_affiliates", action="insert_carrier_safe_harbor_carveout")
        ]
        for r in rules:
            db.add(r)

        c1 = Contract(
            id="contract-001",
            lease_id="lease-001-dallas",
            contract_number="VB-MLA-2024-001",
            contract_type="master_lease",
            title="Cell Tower Master Ground Lease Agreement - Dallas Alpha",
            status="active",
            signed_date=now - timedelta(days=365)
        )
        c2 = Contract(
            id="contract-002",
            lease_id="lease-002-houston",
            contract_number="VB-COLO-2024-002",
            contract_type="colocation_agreement",
            title="Carrier 5G Antenna Space Colocation License - Verizon",
            status="active",
            signed_date=now - timedelta(days=200)
        )
        db.add(c1)
        db.add(c2)
        db.commit()

        clauses = [
            Clause(id="cl-01", contract_id="c1", clause_number="Section 14.2", title="Remedies on Default", content="Landlord holds unilateral termination right upon 30 days notice for default with only a 15-day monetary cure period.", page_number=14),
            Clause(id="cl-02", contract_id="c1", clause_number="Section 4.3", title="Annual Rent Adjustments", content="Rent escalator is linked to regional CPI-U with a 2.5% minimum floor.", page_number=5),
            Clause(id="cl-03", contract_id="c1", clause_number="Section 11.1", title="Assignment & Subletting Rights", content="Subleasing antenna space to third-party wireless carriers requires prior written consent from landlord.", page_number=11)
        ]
        for cl in clauses:
            db.add(cl)
        db.commit()

        print("6. Seeding Operations Workflows, Runs, and Tasks...")
        db.query(Approval).delete()
        db.query(Task).delete()
        db.query(WorkflowRun).delete()
        db.query(Workflow).delete()

        wf1 = Workflow(id="wf-01", name="Carrier 5G Colocation Intake & Engineering Review", description="Intake, structural calculation, and lease clearance for new tenant antennas.", workflow_type="colocation_intake", is_active=True)
        wf2 = Workflow(id="wf-02", name="Quarterly FAA Tower Lighting & Monitoring Certification", description="Verification of dual medium-intensity white/red beacon operation.", workflow_type="compliance", is_active=True)
        wf3 = Workflow(id="wf-03", name="180-Day Ground Lease Option Exercise Protocol", description="Formal legal notification and certified escrow delivery for extension options.", workflow_type="lease_renewal", is_active=True)
        db.add_all([wf1, wf2, wf3])
        db.commit()

        run1 = WorkflowRun(id="wfr-01", workflow_id="wf-01", status="in_progress", started_at=now - timedelta(days=5), assigned_to="operations_director@verticalbridge.com", tower_site_id="vb-001-dallas")
        run2 = WorkflowRun(id="wfr-02", workflow_id="wf-02", status="completed", started_at=now - timedelta(days=30), completed_at=now - timedelta(days=28), assigned_to="field_engineering@verticalbridge.com", tower_site_id="vb-001-dallas")
        db.add_all([run1, run2])
        db.commit()

        tasks = [
            Task(id="task-01", title="TIA-222-H Structural Wind & Ice Load Analysis", description="Review 64T64R Massive MIMO antenna addition for wind load compliance.", status="in_progress", priority="high", due_date=now + timedelta(days=7), assigned_to="structural_lead@verticalbridge.com", workflow_run_id="wfr-01"),
            Task(id="task-02", title="Ground Lease Consent Waiver Verification", description="Confirm carrier assignment does not trigger landlord consent barrier.", status="completed", priority="normal", due_date=now - timedelta(days=1), completed_at=now - timedelta(days=2), assigned_to="legal_operations@verticalbridge.com", workflow_run_id="wfr-01"),
            Task(id="task-03", title="NOTAM Submission for Beacon Bulb Replacement", description="Submit Notice to Air Missions to FAA for 24-hour maintenance window.", status="pending", priority="critical", due_date=now + timedelta(days=2), assigned_to="field_tech_dallas@verticalbridge.com", workflow_run_id="wfr-02"),
            Task(id="task-04", title="Serve 180-Day Option Renewal Notice - Houston Central", description="Prepare certified mail option exercise letter to MetroTowers Realty Group.", status="pending", priority="critical", due_date=now + timedelta(days=10), assigned_to="lease_manager@verticalbridge.com")
        ]
        for t in tasks:
            db.add(t)
        db.commit()

        ap = Approval(id="app-01", task_id="task-02", approver_id="general_counsel@verticalbridge.com", status="approved", approved_at=now - timedelta(days=2), comments="Safe harbor carveout confirmed for Tier 1 wireless carriers.")
        db.add(ap)
        db.commit()

        print("7. Initializing Evidence Vault with Seed Events...")
        evidence_vault_service.append_event(
            organization_id=org_id,
            actor_id="system_init",
            action="enterprise_platform_initialized",
            resource_id="platform_root",
            resource_type="system",
            payload={"version": "1.0.0", "modules": ["towers", "leases", "legal", "operations", "contracts", "quantum_security"]}
        )
        evidence_vault_service.append_event(
            organization_id=org_id,
            actor_id="operations_lead",
            action="ground_lease_baseline_loaded",
            resource_id="lease-001-dallas",
            resource_type="lease",
            payload={"lease_number": "VB-LEASE-2024-001", "annual_rent": 480000.0}
        )
        evidence_vault_service.create_checkpoint(organization_id=org_id)

        print("Successfully seeded all enterprise modules!")

    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_enterprise()

