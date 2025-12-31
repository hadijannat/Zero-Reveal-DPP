"""
zero_reveal_dpp/tiers.py
EU Battery Regulation disclosure tier management.
"""
from enum import Enum
from dataclasses import dataclass
from typing import Set, Dict, List

from .merkle import SaltedMerkleTree, MerkleProof


class DisclosureTier(Enum):
    """Access control tiers per EU Battery Regulation Annex XIII."""
    PUBLIC = "public"  # Point 1: All consumers
    AUTHORITIES = "authorities"  # Points 2-3: Notified bodies, EC
    LEGITIMATE_INTEREST = "legitimate_interest"  # Point 4: Recyclers, repairers
    CONFIDENTIAL = "confidential"  # Trade secrets (never disclosed)


# EU Battery Regulation Annex XIII field mappings
EU_BATTERY_TIER_MAPPING: Dict[DisclosureTier, Set[str]] = {
    DisclosureTier.PUBLIC: {
        "generalProductInformation.batteryId",
        "generalProductInformation.manufacturerName",
        "generalProductInformation.manufacturingDate",
        "generalProductInformation.manufacturingPlace",
        "generalProductInformation.batteryCategory",
        "generalProductInformation.batteryWeight",
        "generalProductInformation.batteryChemistry",
        "carbonFootprint.batteryCarbonFootprint",
        "carbonFootprint.carbonFootprintPerformanceClass",
        "materialComposition.hazardousSubstances.containsCadmium",
        "materialComposition.hazardousSubstances.containsLead",
        "labelsAndCertification.ceMarking",
        "circularity.safetyMeasures",
    },
    DisclosureTier.AUTHORITIES: {
        "carbonFootprint.carbonFootprintStudyUrl",
        "labelsAndCertification.declarationOfConformityUrl",
        "supplyChainDueDiligence.dueDiligenceReportUrl",
        "supplyChainDueDiligence.thirdPartyVerified",
        "materialComposition.recycledContentCobalt",
        "materialComposition.recycledContentLithium",
    },
    DisclosureTier.LEGITIMATE_INTEREST: {
        "performanceAndDurability.ratedCapacity",
        "performanceAndDurability.stateOfHealth",
        "performanceAndDurability.fullChargeCycles",
        "circularity.dismantlingInstructions",
        "materialComposition.criticalRawMaterials",
    },
    DisclosureTier.CONFIDENTIAL: {
        # These fields are NEVER disclosed via proofs
        # Only included for documentation
        "supplyChainDueDiligence.supplierIdentities",
        "manufacturingProcess.proprietaryParameters",
        "bmsAlgorithms.proprietaryLogic",
    }
}


@dataclass
class TierProofBundle:
    """Bundle of proofs for an entire disclosure tier."""
    tier: DisclosureTier
    proofs: List[MerkleProof]
    merkle_root: str
    fields_disclosed: List[str]
    fields_not_found: List[str]  # Fields in tier but not in passport


class TieredDisclosure:
    """Manages tier-based selective disclosure."""
    
    def __init__(
        self, 
        tree: SaltedMerkleTree,
        tier_mapping: Dict[DisclosureTier, Set[str]] = None
    ):
        self.tree = tree
        self.tier_mapping = tier_mapping or EU_BATTERY_TIER_MAPPING
    
    def generate_tier_bundle(self, tier: DisclosureTier) -> TierProofBundle:
        """Generate proofs for all fields in a disclosure tier.
        
        Args:
            tier: Disclosure tier to generate proofs for
            
        Returns:
            TierProofBundle with all available proofs
            
        Raises:
            ValueError: If requesting CONFIDENTIAL tier
        """
        if tier == DisclosureTier.CONFIDENTIAL:
            raise ValueError("Cannot generate proofs for CONFIDENTIAL tier")
        
        fields = self.tier_mapping.get(tier, set())
        proofs = []
        disclosed = []
        not_found = []
        
        for field in sorted(fields):
            try:
                proof = self.tree.generate_proof(field)
                proofs.append(proof)
                disclosed.append(field)
            except ValueError:
                not_found.append(field)
        
        return TierProofBundle(
            tier=tier,
            proofs=proofs,
            merkle_root=self.tree.get_root().hex(),
            fields_disclosed=disclosed,
            fields_not_found=not_found
        )
    
    def verify_tier_bundle(self, bundle: TierProofBundle) -> bool:
        """Verify all proofs in a tier bundle.
        
        Args:
            bundle: TierProofBundle to verify
            
        Returns:
            True if ALL proofs are valid, False otherwise
        """
        root = bytes.fromhex(bundle.merkle_root)
        
        for proof in bundle.proofs:
            if not SaltedMerkleTree.verify_proof(proof, root):
                return False
        
        return True
