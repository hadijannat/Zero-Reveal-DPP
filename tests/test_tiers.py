"""
tests/test_tiers.py
Unit tests for disclosure tier management.
"""
import pytest
from zero_reveal_dpp.merkle import SaltedMerkleTree
from zero_reveal_dpp.tiers import (
    DisclosureTier,
    EU_BATTERY_TIER_MAPPING,
    TierProofBundle,
    TieredDisclosure
)


@pytest.fixture
def battery_passport():
    """Sample battery passport data."""
    return {
        "generalProductInformation": {
            "batteryId": "BATT-2025-EU-001234",
            "manufacturerName": "EuroCell GmbH",
            "manufacturingDate": "2025-03-15",
            "manufacturingPlace": "Berlin, Germany",
            "batteryCategory": "EV",
            "batteryWeight": 450.0,
            "batteryChemistry": "NMC811"
        },
        "carbonFootprint": {
            "batteryCarbonFootprint": 61.5,
            "carbonFootprintPerformanceClass": "B",
            "carbonFootprintStudyUrl": "https://eurocell.example/cf-2025.pdf"
        },
        "materialComposition": {
            "criticalRawMaterials": ["lithium", "cobalt", "nickel"],
            "recycledContentCobalt": 16.0,
            "recycledContentLithium": 6.0,
            "hazardousSubstances": {
                "containsCadmium": False,
                "containsLead": False
            }
        },
        "performanceAndDurability": {
            "ratedCapacity": 75.0,
            "stateOfHealth": 98.5,
            "fullChargeCycles": 142
        },
        "labelsAndCertification": {
            "ceMarking": True,
            "declarationOfConformityUrl": "https://eurocell.example/doc-2025.pdf"
        }
    }


@pytest.fixture
def tree_and_tiered(battery_passport):
    """Create tree and tiered disclosure instance."""
    tree = SaltedMerkleTree.from_passport(battery_passport)
    tiered = TieredDisclosure(tree)
    return tree, tiered


class TestDisclosureTierEnum:
    """Tests for DisclosureTier enum."""
    
    def test_tier_values(self):
        """Tiers should have correct string values."""
        assert DisclosureTier.PUBLIC.value == "public"
        assert DisclosureTier.AUTHORITIES.value == "authorities"
        assert DisclosureTier.LEGITIMATE_INTEREST.value == "legitimate_interest"
        assert DisclosureTier.CONFIDENTIAL.value == "confidential"
    
    def test_tier_count(self):
        """Should have exactly 4 tiers."""
        assert len(DisclosureTier) == 4


class TestEUBatteryTierMapping:
    """Tests for EU Battery Regulation tier mappings."""
    
    def test_public_tier_has_fields(self):
        """PUBLIC tier should have required fields."""
        public_fields = EU_BATTERY_TIER_MAPPING[DisclosureTier.PUBLIC]
        assert "generalProductInformation.batteryId" in public_fields
        assert "carbonFootprint.batteryCarbonFootprint" in public_fields
    
    def test_authorities_tier_has_fields(self):
        """AUTHORITIES tier should have audit fields."""
        auth_fields = EU_BATTERY_TIER_MAPPING[DisclosureTier.AUTHORITIES]
        assert "supplyChainDueDiligence.thirdPartyVerified" in auth_fields
    
    def test_confidential_tier_exists(self):
        """CONFIDENTIAL tier should be defined."""
        conf_fields = EU_BATTERY_TIER_MAPPING[DisclosureTier.CONFIDENTIAL]
        assert len(conf_fields) > 0
    
    def test_tiers_are_disjoint(self):
        """Fields should not appear in multiple tiers."""
        all_fields = []
        for tier in [DisclosureTier.PUBLIC, DisclosureTier.AUTHORITIES, 
                     DisclosureTier.LEGITIMATE_INTEREST]:
            all_fields.extend(EU_BATTERY_TIER_MAPPING[tier])
        
        assert len(all_fields) == len(set(all_fields)), "Duplicate fields across tiers"


class TestTieredDisclosure:
    """Tests for TieredDisclosure class."""
    
    def test_generate_public_bundle(self, tree_and_tiered):
        """Should generate bundle for PUBLIC tier."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
        
        assert isinstance(bundle, TierProofBundle)
        assert bundle.tier == DisclosureTier.PUBLIC
        assert len(bundle.proofs) > 0
        assert len(bundle.fields_disclosed) > 0
    
    def test_generate_authorities_bundle(self, tree_and_tiered):
        """Should generate bundle for AUTHORITIES tier."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.AUTHORITIES)
        
        assert bundle.tier == DisclosureTier.AUTHORITIES
        assert len(bundle.proofs) > 0
    
    def test_generate_legitimate_interest_bundle(self, tree_and_tiered):
        """Should generate bundle for LEGITIMATE_INTEREST tier."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.LEGITIMATE_INTEREST)
        
        assert bundle.tier == DisclosureTier.LEGITIMATE_INTEREST
        assert len(bundle.proofs) > 0
    
    def test_confidential_tier_rejected(self, tree_and_tiered):
        """Should reject CONFIDENTIAL tier proof generation."""
        tree, tiered = tree_and_tiered
        
        with pytest.raises(ValueError, match="Cannot generate proofs for CONFIDENTIAL tier"):
            tiered.generate_tier_bundle(DisclosureTier.CONFIDENTIAL)
    
    def test_fields_not_found_tracked(self, tree_and_tiered):
        """Missing fields should be tracked in not_found list."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
        
        # circularity.safetyMeasures is in PUBLIC but not in our test passport
        assert "circularity.safetyMeasures" in bundle.fields_not_found
    
    def test_merkle_root_in_bundle(self, tree_and_tiered):
        """Bundle should contain correct Merkle root."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
        
        assert bundle.merkle_root == tree.get_root().hex()


class TestBundleVerification:
    """Tests for bundle verification."""
    
    def test_verify_valid_bundle(self, tree_and_tiered):
        """Valid bundle should verify successfully."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
        
        assert tiered.verify_tier_bundle(bundle) is True
    
    def test_verify_authorities_bundle(self, tree_and_tiered):
        """Authorities bundle should verify."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.AUTHORITIES)
        
        assert tiered.verify_tier_bundle(bundle) is True
    
    def test_verify_tampered_bundle_fails(self, tree_and_tiered):
        """Tampered bundle should fail verification."""
        tree, tiered = tree_and_tiered
        bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
        
        # Tamper with a proof value
        if bundle.proofs:
            bundle.proofs[0].value = "tampered"
        
        assert tiered.verify_tier_bundle(bundle) is False
    
    def test_verify_empty_bundle(self, tree_and_tiered):
        """Empty bundle should verify (vacuously true)."""
        tree, tiered = tree_and_tiered
        
        # Create a tier with no matching fields
        custom_mapping = {DisclosureTier.PUBLIC: {"nonexistent.field"}}
        custom_tiered = TieredDisclosure(tree, tier_mapping=custom_mapping)
        bundle = custom_tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
        
        assert len(bundle.proofs) == 0
        assert custom_tiered.verify_tier_bundle(bundle) is True


class TestCustomTierMapping:
    """Tests for custom tier mappings."""
    
    def test_custom_mapping(self, battery_passport):
        """Should accept custom tier mapping."""
        tree = SaltedMerkleTree.from_passport(battery_passport)
        
        custom_mapping = {
            DisclosureTier.PUBLIC: {
                "carbonFootprint.batteryCarbonFootprint"
            }
        }
        
        tiered = TieredDisclosure(tree, tier_mapping=custom_mapping)
        bundle = tiered.generate_tier_bundle(DisclosureTier.PUBLIC)
        
        assert len(bundle.proofs) == 1
        assert bundle.fields_disclosed == ["carbonFootprint.batteryCarbonFootprint"]
