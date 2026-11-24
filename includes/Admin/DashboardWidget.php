<?php
/**
 * DashboardWidget - WebCare Pro Security & Firewall Overview Widget
 *
 * Renders a lightweight, high-contrast, zero-DB bloat security status card
 * directly on the WordPress admin dashboard (wp-admin/index.php).
 *
 * @package WebCareProScanner\Admin
 * @since 3.24.0
 */

declare(strict_types=1);

namespace WebCareProScanner\Admin;

if (!defined('ABSPATH')) {
    exit;
}

use WebCareProScanner\Firewall\Core\WafVaultManager;
use WebCareProScanner\Firewall\WafFileLogger;
use WebCareProScanner\Firewall\RescueAssistantManager;

final class DashboardWidget {

    /**
     * Register the security overview dashboard widget.
     */
    public static function register(): void {
        if (!current_user_can('manage_options')) {
            return;
        }

        wp_add_dashboard_widget(
            'webcareproscan_security_overview',
            esc_html__('WebCare Pro — Security Overview', 'webcare-pro-security'),
            [self::class, 'render']
        );
    }

    /**
     * Render the dashboard widget content.
     */
    public static function render(): void {
        // 1. Safe Mode / Protection Status (O(1) memory/transient lookup)
        $pause_state = class_exists(RescueAssistantManager::class) ? RescueAssistantManager::get_pause_status() : [];
        $is_safe_mode = !empty($pause_state['paused']);
        $safe_mode_remaining = (int) ($pause_state['seconds_remaining'] ?? 0);

        // 2. Metrics (O(1) JSON file/vault lookups, zero heavy SQL)
        $today_stats = class_exists(WafFileLogger::class) ? WafFileLogger::get_log_stats('today') : [];
        $blocks_today = (int) ($today_stats['blocked_24h'] ?? 0);

        $week_stats = class_exists(WafFileLogger::class) ? WafFileLogger::get_log_stats('7days') : [];
        $blocks_7days = (int) ($week_stats['blocked_24h'] ?? 0);
        if ($blocks_7days < $blocks_today) {
            $blocks_7days = $blocks_today;
        }

        // 3. Last Scan Finding Summary
        $last_scan = get_option('webcareproscan_last_scan_summary', []);
        $total_findings = 0;
        $scan_date = '';
        if (is_array($last_scan)) {
            $total_findings = (int) ($last_scan['total_issues'] ?? ($last_scan['issues_count'] ?? 0));
            if (!empty($last_scan['completed_at'])) {
                $scan_date = date_i18n(get_option('date_format'), (int) $last_scan['completed_at']);
            }
        }

        // URLs
        $dashboard_url = \WebCareProScanner\Admin\RouteRegistry::url('webcare-pro-security');
        $waf_logs_url  = \WebCareProScanner\Admin\RouteRegistry::url('webcare-pro-logs');
        $scanner_url   = \WebCareProScanner\Admin\RouteRegistry::url('webcare-pro-scanner');

        ?>
        <div class="webcare-widget-wrapper" style="margin: -6px -12px -12px; padding: 14px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, sans-serif;">
            <style>
                .webcare-widget-header {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    flex-wrap: wrap;
                    gap: 8px;
                    padding-bottom: 12px;
                    border-bottom: 1px solid #e2e8f0;
                    margin-bottom: 12px;
                }
                .webcare-status-pill {
                    display: inline-flex;
                    align-items: center;
                    gap: 6px;
                    padding: 4px 10px;
                    border-radius: 9999px;
                    font-size: 12px;
                    font-weight: 600;
                }
                .webcare-status-protected {
                    background: #ecfdf5;
                    color: #047857;
                    border: 1px solid #a7f3d0;
                }
                .webcare-status-safe {
                    background: #fffbeb;
                    color: #b45309;
                    border: 1px solid #fde68a;
                }
                .webcare-privacy-tag {
                    font-size: 11px;
                    color: #64748b;
                    display: inline-flex;
                    align-items: center;
                    gap: 4px;
                }
                .webcare-kpi-grid {
                    display: grid;
                    grid-template-columns: repeat(3, 1fr);
                    gap: 8px;
                    margin-bottom: 14px;
                }
                .webcare-kpi-box {
                    background: #f8fafc;
                    border: 1px solid #e2e8f0;
                    border-radius: 6px;
                    padding: 10px 8px;
                    text-align: center;
                }
                .webcare-kpi-num {
                    font-size: 18px;
                    font-weight: 700;
                    line-height: 1.2;
                    margin-bottom: 2px;
                }
                .webcare-kpi-label {
                    font-size: 11px;
                    color: #64748b;
                    font-weight: 500;
                    line-height: 1.3;
                }
                .webcare-widget-footer {
                    display: flex;
                    align-items: center;
                    justify-content: space-between;
                    flex-wrap: wrap;
                    gap: 8px;
                    padding-top: 10px;
                    border-top: 1px solid #e2e8f0;
                }
                .webcare-widget-links {
                    display: inline-flex;
                    align-items: center;
                    gap: 12px;
                    font-size: 12px;
                }
                .webcare-widget-links a {
                    color: #4f46e5;
                    text-decoration: none;
                    font-weight: 500;
                }
                .webcare-widget-links a:hover {
                    text-decoration: underline;
                    color: #4338ca;
                }
                @media (max-width: 480px) {
                    .webcare-kpi-grid {
                        grid-template-columns: 1fr;
                    }
                }
            </style>

            <!-- 1. Header Status Strip -->
            <div class="webcare-widget-header">
                <div>
                    <?php if ($is_safe_mode) : ?>
                        <span class="webcare-status-pill webcare-status-safe">
                            <span class="dashicons dashicons-warning" style="font-size: 14px; line-height: 1;"></span>
                            <?php
                            $min = floor($safe_mode_remaining / 60);
                            $sec = $safe_mode_remaining % 60;
                            /* translators: 1: minutes, 2: seconds */
                            echo esc_html(sprintf(__('Safe Mode Active (%1$02d:%2$02d left)', 'webcare-pro-security'), $min, $sec));
                            ?>
                        </span>
                    <?php else : ?>
                        <span class="webcare-status-pill webcare-status-protected">
                            <span class="dashicons dashicons-shield-alt" style="font-size: 14px; line-height: 1;"></span>
                            <?php esc_html_e('Your Site is Protected · Firewall Active', 'webcare-pro-security'); ?>
                        </span>
                    <?php endif; ?>
                </div>
                <div class="webcare-privacy-tag">
                    <span class="dashicons dashicons-lock" style="font-size: 12px; line-height: 1;"></span>
                    <?php esc_html_e('100% Local · Zero Telemetry', 'webcare-pro-security'); ?>
                </div>
            </div>

            <!-- 2. 3-Column Metric Row -->
            <div class="webcare-kpi-grid">
                <div class="webcare-kpi-box">
                    <div class="webcare-kpi-num" style="color: #0f172a;">
                        <?php echo esc_html(number_format_i18n($blocks_today)); ?>
                    </div>
                    <div class="webcare-kpi-label">
                        <?php esc_html_e('Blocked Today', 'webcare-pro-security'); ?>
                        <div style="font-size: 9.5px; color: #94a3b8;"><?php esc_html_e('Automated probes stopped', 'webcare-pro-security'); ?></div>
                    </div>
                </div>

                <div class="webcare-kpi-box">
                    <div class="webcare-kpi-num" style="color: #4f46e5;">
                        <?php echo esc_html(number_format_i18n($blocks_7days)); ?>
                    </div>
                    <div class="webcare-kpi-label">
                        <?php esc_html_e('7-Day Protection', 'webcare-pro-security'); ?>
                        <div style="font-size: 9.5px; color: #94a3b8;"><?php esc_html_e('Shoppers unaffected', 'webcare-pro-security'); ?></div>
                    </div>
                </div>

                <div class="webcare-kpi-box">
                    <?php if ($total_findings === 0) : ?>
                        <div class="webcare-kpi-num" style="color: #059669; font-size: 15px; margin-top: 2px;">
                            <span class="dashicons dashicons-yes-alt" style="font-size: 16px; line-height: 1; vertical-align: -2px;"></span>
                            <?php esc_html_e('All Clear', 'webcare-pro-security'); ?>
                        </div>
                        <div class="webcare-kpi-label">
                            <?php esc_html_e('Last Site Check', 'webcare-pro-security'); ?>
                            <?php if ($scan_date) : ?>
                                <div style="font-size: 9.5px; color: #94a3b8;"><?php echo esc_html($scan_date); ?></div>
                            <?php endif; ?>
                        </div>
                    <?php else : ?>
                        <div class="webcare-kpi-num" style="color: #d97706; font-size: 15px; margin-top: 2px;">
                            <?php
                            /* translators: %d: number of findings */
                            echo esc_html(sprintf(_n('%d Item to Review', '%d Items to Review', $total_findings, 'webcare-pro-security'), $total_findings));
                            ?>
                        </div>
                        <div class="webcare-kpi-label">
                            <?php esc_html_e('Last Site Check', 'webcare-pro-security'); ?>
                            <div style="font-size: 9.5px; color: #94a3b8;"><?php esc_html_e('Action optional', 'webcare-pro-security'); ?></div>
                        </div>
                    <?php endif; ?>
                </div>
            </div>

            <!-- 3. 1-Click Action Footer -->
            <div class="webcare-widget-footer">
                <a href="<?php echo esc_url($dashboard_url); ?>" class="button button-primary" style="background: #4f46e5; border-color: #4338ca; font-weight: 600; font-size: 12px; height: 30px; line-height: 28px;">
                    <?php esc_html_e('Open Security Dashboard', 'webcare-pro-security'); ?>
                </a>

                <div class="webcare-widget-links">
                    <a href="<?php echo esc_url($waf_logs_url); ?>">
                        <?php esc_html_e('View Firewall Logs', 'webcare-pro-security'); ?>
                    </a>
                    <span>·</span>
                    <a href="<?php echo esc_url($scanner_url); ?>">
                        <?php esc_html_e('Run Quick Check', 'webcare-pro-security'); ?>
                    </a>
                </div>
            </div>
        </div>
        <?php
    }
}
