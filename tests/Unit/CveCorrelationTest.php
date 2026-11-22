<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\CVEIntelligenceService;
use WebCareProScanner\WordPress\UpdateScanner;

/**
 * Unit tests for PR-F:
 * Accurate CVE Applicability Model, Boolean NVD Tree & Full Theme/MU Inventory (Finding #4).
 *
 * Requirements:
 * 1. CVE-2023-28121 attribution to woocommerce-payments only (not woocommerce).
 * 2. Recursive Boolean evaluation for NVD configurations (AND, OR, negate, vulnerable flags).
 * 3. Tri-state version range semantics:
 *    - Bounded exclusive (< 2.0.0)
 *    - Bounded inclusive (<= 2.0.0)
 *    - Valid open-ended (>= 3.0.0)
 *    - Empty / ambiguous (unknown)
 * 4. Complete local component inventory: MU plugins, drop-ins, inactive themes.
 */
final class CveCorrelationTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $GLOBALS['wp_mock_options'] = [];
        $GLOBALS['wp_mock_transients'] = [];
    }

    /**
     * 1. Test CVE-2023-28121 matches woocommerce-payments only and not woocommerce.
     */
    public function testCve202328121Attribution(): void
    {
        $scanner = new UpdateScanner();

        // Query catalog for woocommerce
        $wcCves = UpdateScanner::get_plugin_cves('woocommerce', '5.0.0');
        $wcCveIds = array_column($wcCves, 'cve_id');
        $this->assertNotContains('CVE-2023-28121', $wcCveIds, 'CVE-2023-28121 must NOT be attributed to woocommerce core plugin.');

        // Query catalog for woocommerce-payments
        $wcpCves = UpdateScanner::get_plugin_cves('woocommerce-payments', '5.0.0');
        $wcpCveIds = array_column($wcpCves, 'cve_id');
        $this->assertContains('CVE-2023-28121', $wcpCveIds, 'CVE-2023-28121 MUST be attributed to woocommerce-payments.');
    }

    /**
     * 2. Test recursive Boolean evaluation for NVD configurations (AND, OR, negate).
     */
    public function testRecursiveNvdBooleanTree(): void
    {
        // Scenario A: AND node requiring vulnerable plugin AND specific condition
        // Child 1 matches (vulnerable plugin v1.5.0 < 2.0.0)
        // Child 2 does NOT match (same component, but patched condition not met)
        $andNode = [
            'operator' => 'AND',
            'nodes'    => [
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable'            => true,
                            'criteria'              => 'cpe:2.3:a:automattic:woocommerce-payments:*:*:*:*:*:*:*:*',
                            'versionEndExcluding'   => '2.0.0',
                        ],
                    ],
                ],
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable'          => true,
                            'criteria'            => 'cpe:2.3:a:automattic:woocommerce-payments:*:*:*:*:*:*:*:*',
                            'versionStartIncluding' => '2.5.0',
                            'versionEndIncluding'   => '3.0.0',
                        ],
                    ],
                ],
            ],
        ];

        // Evaluating against woocommerce-payments 1.5.0: child 1 is vulnerable, child 2 is not_vulnerable -> overall not_vulnerable
        $resAnd = CVEIntelligenceService::evaluate_nvd_boolean_tree($andNode, 'woocommerce-payments', '1.5.0');
        $this->assertSame('not_vulnerable', $resAnd, 'AND node must NOT false-positive when one required branch fails.');

        // Scenario B: OR node with one matching vulnerable cpeMatch
        $orNode = [
            'operator' => 'OR',
            'cpeMatch' => [
                [
                    'vulnerable'          => true,
                    'criteria'            => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                    'versionEndExcluding' => '3.6.3',
                ],
                [
                    'vulnerable'          => true,
                    'criteria'            => 'cpe:2.3:a:elementor:elementor-pro:*:*:*:*:*:*:*:*',
                    'versionEndExcluding' => '3.7.0',
                ],
            ],
        ];

        $resOrMatch = CVEIntelligenceService::evaluate_nvd_boolean_tree($orNode, 'elementor', '3.5.0');
        $this->assertSame('vulnerable', $resOrMatch, 'OR node must evaluate to vulnerable when one cpeMatch matches.');

        $resOrClean = CVEIntelligenceService::evaluate_nvd_boolean_tree($orNode, 'elementor', '3.6.4');
        $this->assertSame('not_vulnerable', $resOrClean, 'OR node must evaluate to not_vulnerable when version is patched.');

        // Scenario C: Negate = true inversion
        $negateNode = [
            'operator' => 'OR',
            'negate'   => true,
            'cpeMatch' => [
                [
                    'vulnerable'          => true,
                    'criteria'            => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                    'versionEndExcluding' => '3.6.3',
                ],
            ],
        ];

        // 3.5.0 would be vulnerable without negate, so with negate: true it must become not_vulnerable
        $resNegated = CVEIntelligenceService::evaluate_nvd_boolean_tree($negateNode, 'elementor', '3.5.0');
        $this->assertSame('not_vulnerable', $resNegated, 'negate: true must invert vulnerable result.');

        // Scenario D: AND node where child 1 is vulnerable and child 2 is unknown -> overall must be unknown (NOT vulnerable or not_vulnerable)
        $andWithUnknownNode = [
            'operator' => 'AND',
            'nodes'    => [
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable'          => true,
                            'criteria'            => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                            'versionEndExcluding' => '3.6.3',
                        ],
                    ],
                ],
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable' => true,
                            'criteria'   => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                            // missing version info -> unknown
                        ],
                    ],
                ],
            ],
        ];
        $resAndUnknown = CVEIntelligenceService::evaluate_nvd_boolean_tree($andWithUnknownNode, 'elementor', '3.5.0');
        $this->assertSame('unknown', $resAndUnknown, 'AND node with vulnerable + unknown branch must evaluate to unknown.');

        // Scenario E: Cross-product AND node containing prerequisite leaf for a different component
        $crossProductAndNode = [
            'operator' => 'AND',
            'cpeMatch' => [
                [
                    'vulnerable'          => true,
                    'criteria'            => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                    'versionEndExcluding' => '3.6.3',
                ],
                [
                    'vulnerable' => true,
                    'criteria'   => 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
                ],
            ],
        ];
        $resCrossProduct = CVEIntelligenceService::evaluate_nvd_boolean_tree($crossProductAndNode, 'elementor', '3.5.0');
        $this->assertSame('unknown', $resCrossProduct, 'Cross-product AND prerequisite must evaluate to unknown.');

        // Scenario F: Nested AND(OR(target_vuln_cpe), OR(other_product_cpe)) must return unknown
        $nestedAndOrNode = [
            'operator' => 'AND',
            'nodes'    => [
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable'          => true,
                            'criteria'            => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                            'versionEndExcluding' => '3.6.3',
                        ],
                    ],
                ],
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable' => true,
                            'criteria'   => 'cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*',
                        ],
                    ],
                ],
            ],
        ];
        $resNestedAndOr = CVEIntelligenceService::evaluate_nvd_boolean_tree($nestedAndOrNode, 'elementor', '3.5.0');
        $this->assertSame('unknown', $resNestedAndOr, 'Nested AND(OR(target), OR(other_product)) must evaluate to unknown.');

        // Scenario G: Mixed nested OR under conjunction: AND(target_vuln, OR(target_not_vuln, other_platform_cpe)) -> 'unknown'
        $mixedNestedAndOrNode = [
            'operator' => 'AND',
            'children' => [
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable'            => true,
                            'criteria'              => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                            'versionStartIncluding' => '3.0.0',
                            'versionEndIncluding'   => '3.6.0',
                        ],
                    ],
                ],
                [
                    'operator' => 'OR',
                    'cpeMatch' => [
                        [
                            'vulnerable'            => true,
                            'criteria'              => 'cpe:2.3:a:elementor:elementor:*:*:*:*:*:*:*:*',
                            'versionStartIncluding' => '4.0.0', // Non-matching for 3.5.0 -> 'not_vulnerable'
                            'versionEndIncluding'   => '5.0.0',
                        ],
                        [
                            'vulnerable' => true,
                            'criteria'   => 'cpe:2.3:o:microsoft:windows:*:*:*:*:*:*:*:*', // Cross-product leaf -> 'unknown' under conjunction
                        ],
                    ],
                ],
            ],
        ];
        $resMixed = CVEIntelligenceService::evaluate_nvd_boolean_tree($mixedNestedAndOrNode, 'elementor', '3.5.0');
        $this->assertSame('unknown', $resMixed, 'Nested AND(target_vuln, OR(target_not_vuln, other_platform_cpe)) must evaluate the OR child to unknown and parent AND to unknown.');
    }

    /**
     * 3. Test tri-state version range semantics:
     * - Bounded exclusive (< 2.0.0)
     * - Bounded inclusive (<= 2.0.0)
     * - Valid open-ended (>= 3.0.0)
     * - Empty / ambiguous (unknown)
     */
    public function testTriStateVersionRangeSemantics(): void
    {
        // 1. Bounded exclusive (< 2.0.0)
        $boundExc = ['versionEndExcluding' => '2.0.0'];
        $this->assertSame('vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('1.9.9', $boundExc));
        $this->assertSame('not_vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('2.0.0', $boundExc));
        $this->assertSame('not_vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('2.1.0', $boundExc));

        // 2. Bounded inclusive (<= 2.0.0)
        $boundInc = ['versionEndIncluding' => '2.0.0'];
        $this->assertSame('vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('1.9.9', $boundInc));
        $this->assertSame('vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('2.0.0', $boundInc));
        $this->assertSame('not_vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('2.0.1', $boundInc));

        // 3. Valid open-ended lower bound (>= 3.0.0 with no upper bound) -> vulnerable for >= 3.0.0
        $openEnded = ['versionStartIncluding' => '3.0.0'];
        $this->assertSame('vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('3.0.0', $openEnded));
        $this->assertSame('vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('3.5.0', $openEnded));
        $this->assertSame('not_vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('2.9.9', $openEnded));

        // 4. Bounded range with both start and end (>= 1.5.0 and < 2.5.0)
        $boundedSpan = [
            'versionStartIncluding' => '1.5.0',
            'versionEndExcluding'   => '2.5.0',
        ];
        $this->assertSame('not_vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('1.4.9', $boundedSpan));
        $this->assertSame('vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('1.5.0', $boundedSpan));
        $this->assertSame('vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('2.4.9', $boundedSpan));
        $this->assertSame('not_vulnerable', CVEIntelligenceService::evaluate_version_range_tri_state('2.5.0', $boundedSpan));

        // 5. Empty / Ambiguous metadata -> 'unknown' (never assumed vulnerable)
        $this->assertSame('unknown', CVEIntelligenceService::evaluate_version_range_tri_state('1.0.0', []));
        $this->assertSame('unknown', CVEIntelligenceService::evaluate_version_range_tri_state('', $boundInc));
        $this->assertSame('unknown', CVEIntelligenceService::evaluate_version_range_tri_state('0.0.0', $boundInc));
    }

    /**
     * 4. Test complete component inventory includes MU plugins and inactive themes.
     */
    public function testComponentInventoryCompleteness(): void
    {
        // Mock MU plugins
        $mockMuPlugins = [
            'mu-plugin-test.php' => [
                'Name'    => 'Mock MU Security Plugin',
                'Version' => '1.2.0',
            ],
        ];

        // Mock themes including an inactive theme
        $mockThemes = [
            'twentytwentyfour' => new class {
                public function get(string $key) {
                    return $key === 'Name' ? 'Twenty Twenty-Four' : ($key === 'Version' ? '1.1.0' : '');
                }
                public function exists(): bool { return true; }
                public function get_stylesheet_directory(): string { return '/themes/twentytwentyfour'; }
            },
            'inactive-child-theme' => new class {
                public function get(string $key) {
                    return $key === 'Name' ? 'Inactive Child Theme' : ($key === 'Version' ? '0.9.0' : '');
                }
                public function exists(): bool { return true; }
                public function get_stylesheet_directory(): string { return '/themes/inactive-child'; }
            },
        ];

        $GLOBALS['wp_mock_mu_plugins'] = $mockMuPlugins;
        $GLOBALS['wp_mock_themes'] = $mockThemes;

        // Run full inventory audit
        $audit = UpdateScanner::get_detailed_report();

        $this->assertArrayHasKey('mu_plugins', $audit, 'Audit must inventory MU plugins.');
        $this->assertArrayHasKey('dropins', $audit, 'Audit must inventory drop-ins.');
        $this->assertArrayHasKey('themes', $audit, 'Audit must inventory themes.');

        $themeSlugs = array_column($audit['themes'], 'slug');
        $this->assertContains('inactive-child-theme', $themeSlugs, 'Inactive themes must be included in component inventory.');

        $muSlugs = array_column($audit['mu_plugins'], 'slug');
        $this->assertContains('mu-plugin-test', $muSlugs, 'MU plugins must appear in inventory.');

        // Verify unverified drop-ins report status 'unknown' and never falsely 'secure'
        if (!empty($audit['dropins'])) {
            foreach ($audit['dropins'] as $dropin) {
                if (empty($dropin['has_cve'])) {
                    $this->assertSame('unknown', $dropin['status'], 'Drop-in lacking CVE data must report unknown status.');
                }
            }
        }
    }

    /**
     * 5. Test correlate_component returns unknown on ambiguous metadata.
     */
    public function testCorrelateComponentAmbiguousVersionReturnsUnknown(): void {
        // Plugin installed but version constraint is ambiguous or missing
        $corr = CVEIntelligenceService::correlate_component(
            'custom-plugin',
            'Test Vuln',
            'Description',
            'plugin',
            '' // empty version range
        );

        $this->assertSame('unknown', $corr['status']);

        // Test with WordPress core where installed version is known but constraint is ambiguous
        $corrCore = CVEIntelligenceService::correlate_component(
            'wordpress-core',
            'Core Vuln',
            'Description',
            'core',
            'ambiguous-non-version'
        );
        $this->assertSame('unknown', $corrCore['status']);

        // Test with WordPress core when version constraint is missing entirely
        $corrCoreEmpty = CVEIntelligenceService::correlate_component(
            'wordpress-core',
            'Core Vuln',
            'Description',
            'core',
            ''
        );
        $this->assertSame('unknown', $corrCoreEmpty['status'], 'WordPress core with missing version range must return unknown.');
    }
}
