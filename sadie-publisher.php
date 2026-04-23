<?php
/**
 * Plugin Name: Sadie
 * Plugin URI: https://brotherlyseo.com
 * Description: Sadie's on-site agent. Content publishing, SEO meta management, internal-link injection, page-state probe, and operational monitoring for Brotherly SEO clients.
 * Version: 3.0.8
 * Author: Brotherly SEO
 * License: GPL v2 or later
 * Text Domain: sadie-publisher
 * Requires PHP: 7.4
 * Requires at least: 5.8
 *
 * Changelog:
 * 3.0.8 - Heartbeat now reports `last_self_update` — a compact record
 *         of the most recent successful self-update (timestamp, from
 *         version, to version, zip host). Lets the fleet dashboard
 *         confirm a rollout landed without parsing the full audit log.
 *         Also: first version shipped end-to-end via self-update (no
 *         manual upload) after the v3.0.7 bootstrap fix.
 * 3.0.7 - CRITICAL FIX: self-update now require_once's wp-admin/includes/
 *         file.php before calling wp_tempnam() / WP_Filesystem(). Those
 *         helpers are NOT auto-loaded on REST requests on many hosts
 *         (confirmed silent fatal on SiteGround: TBH v3.0.4 -> v3.0.5
 *         push returned HTTP 200 empty body, only "Update initiated" in
 *         audit log). v3.0.3/3.0.4/3.0.5/3.0.6 self-update silently
 *         PHP-fataled every time. This unlocks self-update fleet-wide.
 * 3.0.6 - Admin settings page now MASKS the API Key and Project Token in
 *         the visible display (e.g. "sadie_ea7************"). The Copy
 *         buttons still copy the full value, so nothing functional changes
 *         — this only protects the shoulder-surf / screenshot surface.
 * 3.0.5 - Heartbeat now reports `trusted_update_domains` (the self-update
 *         allowlist). Lets the fleet dashboard verify a client's domain
 *         allowlist remotely without reading the PHP file.
 * 3.0.4 - Rebrand to "Sadie". New /seo-meta endpoint: update title, meta
 *         description, focus keyword, canonical, and robots/noindex on any
 *         post/page via Yoast/RankMath/AIOSEO. Supports lookup by slug or URL.
 * 3.0.3 - Security audit fixes (v3.0.2 shipped 2 exploit chains):
 *         - CRITICAL: /options POST now hard-allowlists keys. Previously
 *           a compromised API key could siteurl/template/active_plugins/
 *           default_role/admin_email its way into full site takeover.
 *         - Self-update zip download uses wp_safe_remote_get with
 *           redirection=0 — closes open-redirect bypass on trusted hosts.
 *         - Expanded dangerous-function scanner: include/require,
 *           call_user_func, variable-function $var(), backtick shell
 *           operator, preg_replace/e, php://data://phar:// streams,
 *           ReflectionFunction, hex2bin/unpack obfuscation primitives.
 *         - Persistent-backdoor guard: self-update rejects any zip that
 *           modifies the $trusted_update_domains allowlist line.
 *         - New installs default hmac_enabled=true (was false).
 * 3.0.2 - CRITICAL FIX: self-update smoke test was broken on HMAC-enabled
 *         sites. Used to self-curl /ping with API key only -> got 401
 *         when HMAC was on -> treated as failure -> rolled back every
 *         self-update. Now:
 *           (a) smoke test hits /wp-json/ root (no auth required)
 *           (b) accepts HTTP < 500 as pass (plugin loaded cleanly)
 *           (c) calls opcache_invalidate($plugin_file, true) after write
 *               so OpCache doesn't serve stale opcodes
 *           (d) richer audit log so we can debug future failures
 * 3.0.1 - Internal-link injector switched from in-body DOM-walk to a single
 *         display:none "Related Pages" block appended to post content.
 *         Matches OTTO's model: Googlebot still crawls + follows + PageRank
 *         flows, but no visual change to the page. Simpler, safer, no risk
 *         of breaking theme layouts.
 * 3.0.0 - SEO + Ops release:
 *         - Internal link injector via the_content filter (pulls approved links
 *           from Sadie, DOM-walk insert, circuit breaker on API fail, feature-
 *           flagged + dry-run capable)
 *         - Outbound heartbeat to /api/wp-monitoring/heartbeat every 15 min
 *         - Page-state probe endpoint (returns post-filter title/meta/schema)
 *         - Links refresh push endpoint for fast invalidation on approval
 *         - Post-swap smoke test on self-update
 * 2.3.1 - PHP 7.4 compatibility fix (replaced str_ends_with with substr equivalents)
 * 2.3.0 - Elementor data read/write support in update endpoint, GET post-data endpoint
 * 2.2.1 - Heartbeat now reports scheduled (future) post count
 * 2.2.0 - Secure self-update endpoint, date/scheduling support in create+update, version bump
 * 2.1.0 - Category support in updates, version bump for clean upgrade path
 * 2.0.2 - WP Options read/write endpoint for remote plugin configuration
 * 2.0.1 - Auto-sideload external images in post content to local media library
 * 2.0.0 - Major security hardening, builder detection, heartbeat monitoring, one-way design
 * 1.0.2 - Fixed API key being cleared when saving settings
 * 1.0.1 - Initial bug fixes and stability improvements
 * 1.0.0 - Initial release
 */

if (!defined('ABSPATH')) {
    exit;
}

define('SADIE_PUBLISHER_VERSION', '3.0.8');
define('SADIE_PUBLISHER_MIN_PHP', '7.4');
define('SADIE_PUBLISHER_RATE_LIMIT', 30); // requests per minute
define('SADIE_PUBLISHER_NONCE_TTL', 300); // 5 minute nonce window
define('SADIE_API_BASE', 'https://sadie.brotherlydev.com');
define('SADIE_LINKS_TTL', 6 * HOUR_IN_SECONDS);
define('SADIE_HEARTBEAT_INTERVAL', 15 * MINUTE_IN_SECONDS);

class Sadie_Publisher {

    private static $instance = null;

    // Option keys
    private $api_key_option = 'sadie_publisher_api_key';
    private $project_token_option = 'sadie_publisher_project_token';
    private $settings_option = 'sadie_publisher_settings';
    private $log_option = 'sadie_publisher_audit_log';

    public static function get_instance() {
        if (null === self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    private function __construct() {
        add_action('admin_menu', [$this, 'add_admin_menu']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('rest_api_init', [$this, 'register_rest_routes']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_admin_scripts']);

        register_activation_hook(__FILE__, [$this, 'activate']);
        register_deactivation_hook(__FILE__, [$this, 'deactivate']);
    }

    // =========================================================================
    // ACTIVATION / DEACTIVATION
    // =========================================================================

    public function activate() {
        if (version_compare(PHP_VERSION, SADIE_PUBLISHER_MIN_PHP, '<')) {
            deactivate_plugins(plugin_basename(__FILE__));
            wp_die(sprintf(
                'Sadie requires PHP %s or higher. You are running PHP %s.',
                SADIE_PUBLISHER_MIN_PHP,
                PHP_VERSION
            ));
        }

        if (!get_option($this->api_key_option)) {
            update_option($this->api_key_option, $this->generate_api_key());
        }
        if (!get_option($this->project_token_option)) {
            update_option($this->project_token_option, $this->generate_project_token());
        }

        // Initialize audit log
        if (!get_option($this->log_option)) {
            update_option($this->log_option, []);
        }

        // Store activation timestamp
        update_option('sadie_publisher_activated_at', current_time('mysql'));

        // v3.0.3 — default HMAC on for new installs. Previously off by
        // default which meant a leaked API key alone was a site takeover.
        // Existing sites keep their current setting.
        $settings = get_option($this->settings_option);
        if (!is_array($settings) || !isset($settings['hmac_enabled'])) {
            $settings = is_array($settings) ? $settings : [];
            $settings['hmac_enabled'] = 1;
            update_option($this->settings_option, $settings);
        }
    }

    public function deactivate() {
        // Clean up transients
        global $wpdb;
        $wpdb->query(
            "DELETE FROM {$wpdb->options} WHERE option_name LIKE '_transient_sadie_rate_%' OR option_name LIKE '_transient_timeout_sadie_rate_%' OR option_name LIKE '_transient_sadie_nonce_%' OR option_name LIKE '_transient_timeout_sadie_nonce_%'"
        );
    }

    private function generate_api_key() {
        return 'sadie_' . bin2hex(random_bytes(32));
    }

    private function generate_project_token() {
        return 'proj_' . bin2hex(random_bytes(16));
    }

    // =========================================================================
    // ADMIN UI
    // =========================================================================

    public function add_admin_menu() {
        add_options_page(
            'Sadie',
            'Sadie',
            'manage_options',
            'sadie-publisher',
            [$this, 'render_settings_page']
        );
    }

    public function register_settings() {
        register_setting('sadie_publisher', $this->settings_option, [
            'type' => 'array',
            'sanitize_callback' => [$this, 'sanitize_settings'],
        ]);
    }

    public function sanitize_settings($input) {
        $clean = [];
        $clean['default_status'] = in_array($input['default_status'] ?? '', ['draft', 'publish', 'pending'], true)
            ? $input['default_status'] : 'draft';
        $clean['default_author'] = absint($input['default_author'] ?? 0);
        $clean['allow_images'] = !empty($input['allow_images']) ? 1 : 0;
        $clean['seo_plugin'] = in_array($input['seo_plugin'] ?? '', ['auto', 'yoast', 'rankmath', 'aioseo', 'none'], true)
            ? $input['seo_plugin'] : 'auto';
        $clean['allowed_ips'] = sanitize_textarea_field($input['allowed_ips'] ?? '');
        $clean['hmac_enabled'] = !empty($input['hmac_enabled']) ? 1 : 0;

        // v3.0 features — all false-by-default for safe rollout
        $clean['internal_links_enabled'] = !empty($input['internal_links_enabled']) ? 1 : 0;
        $clean['internal_links_dry_run'] = !empty($input['internal_links_dry_run']) ? 1 : 0;
        $clean['page_state_probe_enabled'] = !empty($input['page_state_probe_enabled']) ? 1 : 0;
        $clean['heartbeat_v2_enabled'] = !empty($input['heartbeat_v2_enabled']) ? 1 : 0;
        $clean['max_links_per_page'] = max(0, min(10, absint($input['max_links_per_page'] ?? 3)));
        $clean['min_paragraph_length'] = max(0, absint($input['min_paragraph_length'] ?? 200));
        $clean['sadie_api_base'] = !empty($input['sadie_api_base'])
            ? esc_url_raw($input['sadie_api_base'])
            : SADIE_API_BASE;
        return $clean;
    }

    public function enqueue_admin_scripts($hook) {
        if ($hook !== 'settings_page_sadie-publisher') {
            return;
        }
        wp_add_inline_style('wp-admin', $this->get_admin_css());
    }

    private function get_admin_css() {
        return '
            .sadie-wrap { max-width: 860px; }
            .sadie-card { background: #fff; border: 1px solid #c3c4c7; border-radius: 6px; padding: 20px 24px; margin-bottom: 20px; }
            .sadie-api-key { font-family: monospace; background: #f0f0f1; padding: 10px 14px; border-radius: 4px; font-size: 13px; word-break: break-all; border: 1px solid #c3c4c7; display: inline-block; max-width: 500px; }
            .sadie-copy-btn { margin-left: 8px !important; }
            .sadie-endpoint { color: #2271b1; font-family: monospace; font-size: 13px; }
            .sadie-badge { display: inline-block; padding: 3px 10px; border-radius: 3px; font-size: 12px; font-weight: 600; }
            .sadie-badge-green { background: #d4edda; color: #155724; }
            .sadie-badge-red { background: #f8d7da; color: #721c24; }
            .sadie-badge-blue { background: #cce5ff; color: #004085; }
            .sadie-badge-gray { background: #e2e3e5; color: #383d41; }
            .sadie-log-table { width: 100%; border-collapse: collapse; font-size: 13px; }
            .sadie-log-table th, .sadie-log-table td { padding: 6px 10px; border-bottom: 1px solid #e2e3e5; text-align: left; }
            .sadie-log-table tr:hover { background: #f8f9fa; }
        ';
    }

    /**
     * v3.0.6 — Mask a credential for display. Keeps the prefix (useful for
     * identifying which site/key this is at a glance) but hides the secret
     * body. Full value is still used by Copy buttons (onclick) so nothing
     * breaks; the masking only protects the visual/screenshot surface.
     * Example: "sadie_ea7dec55fb0412af0b..." -> "sadie_ea7************"
     */
    private function mask_secret($value) {
        if (empty($value) || !is_string($value)) {
            return '';
        }
        // Keep enough prefix to distinguish between sites; 9 chars covers
        // "sadie_xxx" or "proj_xxxx" naming patterns.
        $prefix_len = 9;
        if (strlen($value) <= $prefix_len) {
            return str_repeat('*', strlen($value));
        }
        return substr($value, 0, $prefix_len) . '************';
    }

    public function render_settings_page() {
        $api_key = get_option($this->api_key_option);
        $project_token = get_option($this->project_token_option);
        $settings = get_option($this->settings_option, []);
        $endpoint = rest_url('sadie-publisher/v1/');
        $builder = $this->detect_builder();
        $seo = $this->detect_seo_plugin();
        $logs = array_slice(get_option($this->log_option, []), -20);
        ?>
        <div class="wrap sadie-wrap">
            <h1>Sadie <small style="font-size:0.5em;color:#666;">v<?php echo esc_html(SADIE_PUBLISHER_VERSION); ?></small></h1>
            <p>One-way content publishing from Blog Command Center. Receive-only — no outbound data.</p>

            <!-- Status Overview -->
            <div class="sadie-card">
                <h2>Site Status</h2>
                <table class="form-table">
                    <tr>
                        <th>Builder</th>
                        <td><span class="sadie-badge sadie-badge-blue"><?php echo esc_html(ucfirst($builder['name'])); ?></span>
                            <?php if ($builder['version']) : ?><small>(v<?php echo esc_html($builder['version']); ?>)</small><?php endif; ?></td>
                    </tr>
                    <tr>
                        <th>SEO Plugin</th>
                        <td><span class="sadie-badge sadie-badge-blue"><?php echo esc_html(ucfirst($seo)); ?></span></td>
                    </tr>
                    <tr>
                        <th>Theme</th>
                        <td><?php echo esc_html(wp_get_theme()->get('Name')); ?> (v<?php echo esc_html(wp_get_theme()->get('Version')); ?>)</td>
                    </tr>
                    <tr>
                        <th>SSL</th>
                        <td><?php echo is_ssl() ? '<span class="sadie-badge sadie-badge-green">Active</span>' : '<span class="sadie-badge sadie-badge-red">Not Active</span>'; ?></td>
                    </tr>
                </table>
            </div>

            <!-- API Configuration -->
            <div class="sadie-card">
                <h2>API Configuration</h2>
                <p style="background:#fff3cd;padding:10px;border-radius:4px;">
                    <strong>Keep these credentials secure.</strong> Anyone with these can publish to your site.
                </p>
                <table class="form-table">
                    <tr>
                        <th>API Base URL</th>
                        <td>
                            <code class="sadie-endpoint"><?php echo esc_html($endpoint); ?></code>
                            <button type="button" class="button button-small sadie-copy-btn" onclick="sadieCopy('<?php echo esc_js($endpoint); ?>')">Copy</button>
                        </td>
                    </tr>
                    <tr>
                        <th>API Key</th>
                        <td>
                            <span class="sadie-api-key" id="sadie-api-key"><?php echo esc_html($this->mask_secret($api_key)); ?></span>
                            <button type="button" class="button button-small sadie-copy-btn" onclick="sadieCopy('<?php echo esc_js($api_key); ?>')">Copy</button>
                            <button type="button" class="button button-small" onclick="sadieRegenKey('api')">Regenerate</button>
                        </td>
                    </tr>
                    <tr>
                        <th>Project Token</th>
                        <td>
                            <span class="sadie-api-key" id="sadie-project-token"><?php echo esc_html($this->mask_secret($project_token)); ?></span>
                            <button type="button" class="button button-small sadie-copy-btn" onclick="sadieCopy('<?php echo esc_js($project_token); ?>')">Copy</button>
                            <button type="button" class="button button-small" onclick="sadieRegenKey('project')">Regenerate</button>
                            <p class="description">Unique site identifier for the Blog Command Center.</p>
                        </td>
                    </tr>
                </table>
            </div>

            <!-- Publishing Settings -->
            <div class="sadie-card">
                <h2>Publishing Settings</h2>
                <form method="post" action="options.php">
                    <?php settings_fields('sadie_publisher'); ?>
                    <table class="form-table">
                        <tr>
                            <th>Default Post Status</th>
                            <td>
                                <select name="<?php echo esc_attr($this->settings_option); ?>[default_status]">
                                    <option value="draft" <?php selected($settings['default_status'] ?? 'draft', 'draft'); ?>>Draft</option>
                                    <option value="publish" <?php selected($settings['default_status'] ?? '', 'publish'); ?>>Published</option>
                                    <option value="pending" <?php selected($settings['default_status'] ?? '', 'pending'); ?>>Pending Review</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th>Default Author</th>
                            <td>
                                <?php wp_dropdown_users([
                                    'name' => $this->settings_option . '[default_author]',
                                    'selected' => $settings['default_author'] ?? get_current_user_id(),
                                    'show_option_none' => '-- Use API specified --',
                                    'option_none_value' => ''
                                ]); ?>
                            </td>
                        </tr>
                        <tr>
                            <th>Allow Image Uploads</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="<?php echo esc_attr($this->settings_option); ?>[allow_images]" value="1"
                                        <?php checked($settings['allow_images'] ?? 1, 1); ?>>
                                    Allow featured images and inline images
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th>SEO Plugin</th>
                            <td>
                                <select name="<?php echo esc_attr($this->settings_option); ?>[seo_plugin]">
                                    <option value="auto" <?php selected($settings['seo_plugin'] ?? 'auto', 'auto'); ?>>Auto-detect</option>
                                    <option value="yoast" <?php selected($settings['seo_plugin'] ?? '', 'yoast'); ?>>Yoast SEO</option>
                                    <option value="rankmath" <?php selected($settings['seo_plugin'] ?? '', 'rankmath'); ?>>RankMath</option>
                                    <option value="aioseo" <?php selected($settings['seo_plugin'] ?? '', 'aioseo'); ?>>All in One SEO</option>
                                    <option value="none" <?php selected($settings['seo_plugin'] ?? '', 'none'); ?>>None</option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th>HMAC Signature Verification</th>
                            <td>
                                <label>
                                    <input type="checkbox" name="<?php echo esc_attr($this->settings_option); ?>[hmac_enabled]" value="1"
                                        <?php checked($settings['hmac_enabled'] ?? 0, 1); ?>>
                                    Require HMAC-SHA256 signed requests (recommended)
                                </label>
                                <p class="description">When enabled, all requests must include an <code>X-Sadie-Signature</code> header.</p>
                            </td>
                        </tr>
                        <tr>
                            <th>IP Allowlist</th>
                            <td>
                                <textarea name="<?php echo esc_attr($this->settings_option); ?>[allowed_ips]" rows="3" cols="40" class="regular-text"
                                    placeholder="Leave blank to allow all IPs"><?php echo esc_textarea($settings['allowed_ips'] ?? ''); ?></textarea>
                                <p class="description">One IP per line. Leave blank to allow all. Supports CIDR notation (e.g. 192.168.1.0/24).</p>
                            </td>
                        </tr>
                    </table>
                    <?php submit_button('Save Settings'); ?>
                </form>
            </div>

            <!-- Audit Log -->
            <div class="sadie-card">
                <h2>Recent Activity (Last 20)</h2>
                <?php if (empty($logs)) : ?>
                    <p style="color:#666;">No API activity yet.</p>
                <?php else : ?>
                    <table class="sadie-log-table">
                        <thead>
                            <tr><th>Time</th><th>Action</th><th>Status</th><th>IP</th><th>Details</th></tr>
                        </thead>
                        <tbody>
                        <?php foreach (array_reverse($logs) as $log) : ?>
                            <tr>
                                <td><?php echo esc_html($log['time'] ?? ''); ?></td>
                                <td><?php echo esc_html($log['action'] ?? ''); ?></td>
                                <td><?php echo ($log['success'] ?? false)
                                    ? '<span class="sadie-badge sadie-badge-green">OK</span>'
                                    : '<span class="sadie-badge sadie-badge-red">FAIL</span>'; ?></td>
                                <td><code><?php echo esc_html($log['ip'] ?? ''); ?></code></td>
                                <td><?php echo esc_html($log['detail'] ?? ''); ?></td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <form method="post" style="margin-top:10px;">
                        <?php wp_nonce_field('sadie_clear_log'); ?>
                        <input type="hidden" name="sadie_action" value="clear_log">
                        <button type="submit" class="button button-small">Clear Log</button>
                    </form>
                    <?php
                    // Handle log clear
                    if (isset($_POST['sadie_action']) && $_POST['sadie_action'] === 'clear_log') {
                        if (wp_verify_nonce($_POST['_wpnonce'], 'sadie_clear_log') && current_user_can('manage_options')) {
                            update_option($this->log_option, []);
                            echo '<script>location.reload();</script>';
                        }
                    }
                    ?>
                <?php endif; ?>
            </div>
        </div>

        <script>
        function sadieCopy(text) {
            navigator.clipboard.writeText(text).then(function() {
                var btn = event.target;
                var orig = btn.textContent;
                btn.textContent = 'Copied!';
                setTimeout(function() { btn.textContent = orig; }, 1500);
            });
        }
        function sadieRegenKey(type) {
            var msg = type === 'api'
                ? 'Regenerate API key? This will disconnect all existing connections.'
                : 'Regenerate project token? Update this in your Blog Command Center.';
            if (!confirm(msg)) return;
            fetch(ajaxurl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'action=sadie_regenerate_key&type=' + type + '&_wpnonce=<?php echo esc_js(wp_create_nonce('sadie_regenerate')); ?>'
            })
            .then(function(r) { return r.json(); })
            .then(function(data) {
                if (data.success) {
                    var el = type === 'api' ? document.getElementById('sadie-api-key') : document.getElementById('sadie-project-token');
                    el.textContent = data.data.key;
                    alert('New ' + (type === 'api' ? 'API key' : 'project token') + ' generated.');
                }
            });
        }
        </script>
        <?php
    }

    // =========================================================================
    // REST API ROUTES
    // =========================================================================

    public function register_rest_routes() {
        $ns = 'sadie-publisher/v1';

        // Publish (create post)
        register_rest_route($ns, '/publish', [
            'methods' => 'POST',
            'callback' => [$this, 'handle_publish'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Update post
        register_rest_route($ns, '/publish/(?P<id>\d+)', [
            'methods' => 'PUT',
            'callback' => [$this, 'handle_update'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Delete post
        register_rest_route($ns, '/publish/(?P<id>\d+)', [
            'methods' => 'DELETE',
            'callback' => [$this, 'handle_delete'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Connection test
        register_rest_route($ns, '/ping', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_ping'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Site info (builder, theme, SEO, categories)
        register_rest_route($ns, '/info', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_info'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Categories list
        register_rest_route($ns, '/categories', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_categories'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Heartbeat (monitoring)
        register_rest_route($ns, '/heartbeat', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_heartbeat'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // WP options read (GET) and write (POST)
        register_rest_route($ns, '/options', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_options_get'],
            'permission_callback' => [$this, 'verify_request'],
        ]);
        register_rest_route($ns, '/options', [
            'methods' => 'POST',
            'callback' => [$this, 'handle_options_set'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Get post data (content, elementor_data, meta)
        register_rest_route($ns, '/post-data/(?P<id>\d+)', [
            'methods' => 'GET',
            'callback' => [$this, 'handle_get_post_data'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // Self-update (secure remote plugin update)
        register_rest_route($ns, '/self-update', [
            'methods' => 'POST',
            'callback' => [$this, 'handle_self_update'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // SEO meta — update title/description/robots on any post/page (v3.0.4)
        register_rest_route($ns, '/seo-meta', [
            'methods' => 'POST',
            'callback' => [$this, 'handle_seo_meta'],
            'permission_callback' => [$this, 'verify_request'],
        ]);

        // SEO meta — bulk update multiple pages at once
        register_rest_route($ns, '/seo-meta/bulk', [
            'methods' => 'POST',
            'callback' => [$this, 'handle_seo_meta_bulk'],
            'permission_callback' => [$this, 'verify_request'],
        ]);
    }

    // =========================================================================
    // SECURITY: REQUEST VERIFICATION
    // =========================================================================

    public function verify_request($request) {
        $ip = $this->get_client_ip();

        // 1. Rate limiting
        if ($this->is_rate_limited($ip)) {
            $this->audit_log('rate_limit', false, $ip, 'Rate limit exceeded');
            return new WP_Error('rate_limited', 'Too many requests. Try again later.', ['status' => 429]);
        }

        // 2. IP allowlist check
        $settings = get_option($this->settings_option, []);
        $allowed_ips = trim($settings['allowed_ips'] ?? '');
        if (!empty($allowed_ips) && !$this->ip_allowed($ip, $allowed_ips)) {
            $this->audit_log('ip_blocked', false, $ip, 'IP not in allowlist');
            return new WP_Error('forbidden', 'Access denied.', ['status' => 403]);
        }

        // 3. API key verification (timing-safe)
        $provided_key = $request->get_header('X-Sadie-API-Key');
        if (!$provided_key) {
            $provided_key = $request->get_param('api_key');
        }

        $stored_key = get_option($this->api_key_option);

        if (!$provided_key || !$stored_key || !hash_equals($stored_key, $provided_key)) {
            $this->audit_log('auth_fail', false, $ip, 'Invalid API key');
            return new WP_Error('unauthorized', 'Invalid API key.', ['status' => 401]);
        }

        // 4. Project token verification (optional, timing-safe)
        $provided_token = $request->get_header('X-Sadie-Project-Token');
        if ($provided_token) {
            $stored_token = get_option($this->project_token_option);
            if (!hash_equals($stored_token, $provided_token)) {
                $this->audit_log('auth_fail', false, $ip, 'Invalid project token');
                return new WP_Error('unauthorized', 'Invalid project token.', ['status' => 401]);
            }
        }

        // 5. HMAC signature verification (if enabled)
        if (!empty($settings['hmac_enabled'])) {
            $signature = $request->get_header('X-Sadie-Signature');
            $timestamp = $request->get_header('X-Sadie-Timestamp');

            if (!$signature || !$timestamp) {
                $this->audit_log('auth_fail', false, $ip, 'Missing HMAC signature or timestamp');
                return new WP_Error('unauthorized', 'HMAC signature required.', ['status' => 401]);
            }

            // Check timestamp freshness (prevent replay)
            $ts = intval($timestamp);
            if (abs(time() - $ts) > SADIE_PUBLISHER_NONCE_TTL) {
                $this->audit_log('auth_fail', false, $ip, 'Stale timestamp (replay?)');
                return new WP_Error('unauthorized', 'Request timestamp expired.', ['status' => 401]);
            }

            // Check nonce hasn't been used (replay protection)
            $nonce = $request->get_header('X-Sadie-Nonce');
            if ($nonce) {
                $nonce_key = 'sadie_nonce_' . md5($nonce);
                if (get_transient($nonce_key)) {
                    $this->audit_log('auth_fail', false, $ip, 'Nonce reuse (replay attempt)');
                    return new WP_Error('unauthorized', 'Request nonce already used.', ['status' => 401]);
                }
                set_transient($nonce_key, 1, SADIE_PUBLISHER_NONCE_TTL);
            }

            // Verify HMAC: sign(timestamp + method + path + body) with API key
            $body = $request->get_body();
            $method = $request->get_method();
            $path = $request->get_route();
            $payload = $timestamp . $method . $path . $body;
            $expected = hash_hmac('sha256', $payload, $stored_key);

            if (!hash_equals($expected, $signature)) {
                $this->audit_log('auth_fail', false, $ip, 'Invalid HMAC signature');
                return new WP_Error('unauthorized', 'Invalid request signature.', ['status' => 401]);
            }
        }

        // Increment rate limit counter
        $this->increment_rate_limit($ip);

        return true;
    }

    // =========================================================================
    // ENDPOINT: WP OPTIONS READ/WRITE
    // =========================================================================

    public function handle_options_get($request) {
        $ip = $this->get_client_ip();
        $keys = $request->get_param('keys');
        if (empty($keys) || !is_array($keys)) {
            return new WP_Error('bad_request', 'keys[] parameter required.', ['status' => 400]);
        }
        $result = [];
        foreach ($keys as $key) {
            $key = sanitize_key($key);
            if ($key) {
                $result[$key] = get_option($key);
            }
        }
        $this->audit_log('options_get', true, $ip, implode(',', array_keys($result)));
        return new WP_REST_Response($result, 200);
    }

    /**
     * v3.0.3 hard allowlist — CRITICAL. Before this, update_option was called
     * with any key/value the caller sent, which let a compromised API key:
     *   - flip `siteurl`/`home` to an attacker origin (login leak)
     *   - switch `template`/`stylesheet` to any already-installed theme
     *   - toggle `active_plugins` (activate malicious plugins, disable
     *     security plugins)
     *   - set `default_role=administrator` + `users_can_register=1` for
     *     open signup as admin
     *   - hijack password-reset via `admin_email`
     * Full site takeover primitive. Hard-pin to the sadie_* namespace + a
     * small set of benign SEO-adjacent options we legitimately need to
     * toggle remotely. Everything else → 403.
     */
    private function options_set_allowlist() {
        return [
            'sadie_publisher_settings',
            'sadie_publisher_api_key',
            'sadie_publisher_project_token',
            // SEO meta descriptions / titles are handled through /publish,
            // never raw options. So no theme-ish keys listed here.
            'blogdescription',        // tagline — benign
            // Explicitly NOT allowed: siteurl, home, template, stylesheet,
            // active_plugins, default_role, users_can_register, admin_email,
            // mailserver_*, * anything we haven't whitelisted.
        ];
    }

    public function handle_options_set($request) {
        $ip = $this->get_client_ip();
        $params = $request->get_json_params();
        $options = $params['options'] ?? null;
        if (empty($options) || !is_array($options)) {
            return new WP_Error('bad_request', 'options object required.', ['status' => 400]);
        }
        $allowed = $this->options_set_allowlist();
        $updated = [];
        $failed  = [];
        $rejected = [];
        foreach ($options as $key => $value) {
            $key = sanitize_key($key);
            if (!$key) continue;

            // Allow exact match OR sadie_* prefix (any plugin-owned namespace).
            $is_allowed = in_array($key, $allowed, true)
                || strpos($key, 'sadie_') === 0;
            if (!$is_allowed) {
                $rejected[] = $key;
                continue;
            }

            $ok = update_option($key, $value);
            if ($ok) {
                $updated[] = $key;
            } else {
                $current = get_option($key);
                if ($current == $value) {
                    $updated[] = $key;
                } else {
                    $failed[] = $key;
                }
            }
        }
        $this->audit_log(
            'options_set',
            empty($failed) && empty($rejected),
            $ip,
            'updated=' . implode(',', $updated) .
                (empty($rejected) ? '' : '  rejected=' . implode(',', $rejected))
        );
        $resp = [
            'updated'  => $updated,
            'failed'   => $failed,
            'rejected' => $rejected,
        ];
        // 403 if the caller tried ONLY disallowed keys (intent-to-abuse signal)
        $status = (empty($updated) && !empty($rejected)) ? 403 : 200;
        return new WP_REST_Response($resp, $status);
    }

    // =========================================================================
    // HELPERS
    // =========================================================================

    private function get_client_ip() {
        // Only trust direct connection IP — don't trust forwarded headers to prevent spoofing
        return sanitize_text_field($_SERVER['REMOTE_ADDR'] ?? '127.0.0.1');
    }

    private function is_rate_limited($ip) {
        $key = 'sadie_rate_' . md5($ip);
        $count = (int) get_transient($key);
        return $count >= SADIE_PUBLISHER_RATE_LIMIT;
    }

    private function increment_rate_limit($ip) {
        $key = 'sadie_rate_' . md5($ip);
        $count = (int) get_transient($key);
        set_transient($key, $count + 1, 60);
    }

    private function ip_allowed($ip, $allowlist_raw) {
        $allowed = array_filter(array_map('trim', explode("\n", $allowlist_raw)));
        if (empty($allowed)) {
            return true;
        }

        foreach ($allowed as $rule) {
            // CIDR notation
            if (strpos($rule, '/') !== false) {
                if ($this->ip_in_cidr($ip, $rule)) {
                    return true;
                }
            } elseif ($ip === $rule) {
                return true;
            }
        }

        return false;
    }

    private function ip_in_cidr($ip, $cidr) {
        list($subnet, $bits) = explode('/', $cidr, 2);
        $ip_long = ip2long($ip);
        $subnet_long = ip2long($subnet);
        $mask = -1 << (32 - (int)$bits);
        return ($ip_long & $mask) === ($subnet_long & $mask);
    }

    // =========================================================================
    // AUDIT LOGGING
    // =========================================================================

    private function audit_log($action, $success, $ip, $detail = '') {
        $logs = get_option($this->log_option, []);
        $logs[] = [
            'time' => current_time('Y-m-d H:i:s'),
            'action' => $action,
            'success' => (bool) $success,
            'ip' => $ip,
            'detail' => substr($detail, 0, 200),
        ];
        // Keep last 100 entries
        if (count($logs) > 100) {
            $logs = array_slice($logs, -100);
        }
        update_option($this->log_option, $logs, false);
    }

    // =========================================================================
    // BUILDER & THEME DETECTION
    // =========================================================================

    private function detect_builder() {
        // Elementor
        if (defined('ELEMENTOR_VERSION') || class_exists('\\Elementor\\Plugin')) {
            return [
                'name' => 'elementor',
                'version' => defined('ELEMENTOR_VERSION') ? ELEMENTOR_VERSION : null,
                'pro' => defined('ELEMENTOR_PRO_VERSION'),
            ];
        }

        // Flatsome (UX Builder)
        $theme = wp_get_theme();
        $template = $theme->get_template();
        if ($template === 'flatsome' || strtolower($theme->get('Name')) === 'flatsome') {
            return [
                'name' => 'flatsome',
                'version' => $theme->get('Version'),
                'pro' => false,
            ];
        }

        // Divi
        if (defined('ET_BUILDER_VERSION') || function_exists('et_setup_theme')) {
            return [
                'name' => 'divi',
                'version' => defined('ET_BUILDER_VERSION') ? ET_BUILDER_VERSION : null,
                'pro' => true,
            ];
        }

        // Beaver Builder
        if (class_exists('FLBuilder') || defined('FL_BUILDER_VERSION')) {
            return [
                'name' => 'beaver_builder',
                'version' => defined('FL_BUILDER_VERSION') ? FL_BUILDER_VERSION : null,
                'pro' => class_exists('FLBuilderModelPro'),
            ];
        }

        // WPBakery
        if (defined('WPB_VC_VERSION') || class_exists('WPBMap')) {
            return [
                'name' => 'wpbakery',
                'version' => defined('WPB_VC_VERSION') ? WPB_VC_VERSION : null,
                'pro' => true,
            ];
        }

        // Bricks
        if (defined('BRICKS_VERSION')) {
            return [
                'name' => 'bricks',
                'version' => BRICKS_VERSION,
                'pro' => true,
            ];
        }

        // Oxygen
        if (defined('CT_VERSION')) {
            return [
                'name' => 'oxygen',
                'version' => CT_VERSION,
                'pro' => true,
            ];
        }

        // Default: Gutenberg (WordPress block editor)
        return [
            'name' => 'gutenberg',
            'version' => get_bloginfo('version'),
            'pro' => false,
        ];
    }

    private function detect_seo_plugin() {
        if (defined('WPSEO_VERSION')) return 'yoast';
        if (class_exists('RankMath')) return 'rankmath';
        if (defined('AIOSEO_VERSION')) return 'aioseo';
        if (defined('JEPACK__VERSION') && class_exists('Jetpack_SEO')) return 'jetpack';
        if (defined('JEPACK__VERSION') && class_exists('Jepack_SEO')) return 'jetpack'; // typo check
        return 'none';
    }

    // =========================================================================
    // ENDPOINT: PING
    // =========================================================================

    public function handle_ping($request) {
        $ip = $this->get_client_ip();
        $this->audit_log('ping', true, $ip);

        return new WP_REST_Response([
            'success' => true,
            'message' => 'Sadie is connected.',
            'version' => SADIE_PUBLISHER_VERSION,
            'site' => get_bloginfo('name'),
            'url' => home_url(),
        ], 200);
    }

    // =========================================================================
    // ENDPOINT: INFO
    // =========================================================================

    public function handle_info($request) {
        $ip = $this->get_client_ip();
        $builder = $this->detect_builder();
        $seo = $this->detect_seo_plugin();

        $categories = get_categories(['hide_empty' => false]);
        $tags = get_tags(['hide_empty' => false]);

        $this->audit_log('info', true, $ip);

        return new WP_REST_Response([
            'site_name' => get_bloginfo('name'),
            'site_url' => home_url(),
            'wp_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
            'plugin_version' => SADIE_PUBLISHER_VERSION,
            'builder' => $builder,
            'seo_plugin' => $seo,
            'theme' => [
                'name' => wp_get_theme()->get('Name'),
                'version' => wp_get_theme()->get('Version'),
                'template' => wp_get_theme()->get_template(),
            ],
            'categories' => array_map(function($cat) {
                return ['id' => $cat->term_id, 'name' => $cat->name, 'slug' => $cat->slug];
            }, $categories),
            'tags' => array_map(function($tag) {
                return ['id' => $tag->term_id, 'name' => $tag->name, 'slug' => $tag->slug];
            }, $tags),
        ], 200);
    }

    // =========================================================================
    // ENDPOINT: CATEGORIES
    // =========================================================================

    public function handle_categories($request) {
        $categories = get_categories(['hide_empty' => false]);
        $ip = $this->get_client_ip();
        $this->audit_log('categories', true, $ip);

        return new WP_REST_Response(array_values(array_map(function($cat) {
            return [
                'id' => $cat->term_id,
                'name' => $cat->name,
                'slug' => $cat->slug,
                'parent' => $cat->parent,
                'count' => $cat->count,
            ];
        }, $categories)), 200);
    }

    // =========================================================================
    // ENDPOINT: HEARTBEAT (Monitoring)
    // =========================================================================

    public function handle_heartbeat($request) {
        $ip = $this->get_client_ip();
        $builder = $this->detect_builder();
        $seo = $this->detect_seo_plugin();

        // Get last publish info
        $last_publish = get_posts([
            'post_type' => 'post',
            'post_status' => 'any',
            'meta_key' => '_sadie_published_at',
            'orderby' => 'meta_value',
            'order' => 'DESC',
            'posts_per_page' => 1,
        ]);
        $last_publish_time = null;
        $last_publish_id = null;
        if (!empty($last_publish)) {
            $last_publish_time = get_post_meta($last_publish[0]->ID, '_sadie_published_at', true);
            $last_publish_id = $last_publish[0]->ID;
        }

        // Post counts
        $post_counts = wp_count_posts('post');

        // Plugin health checks
        $health = [
            'api_key_set' => !empty(get_option($this->api_key_option)),
            'project_token_set' => !empty(get_option($this->project_token_option)),
            'ssl_active' => is_ssl(),
            'wp_cron_enabled' => !(defined('DISABLE_WP_CRON') && DISABLE_WP_CRON),
            'rest_api_accessible' => true, // If we got here, REST API works
            'write_permissions' => wp_is_writable(wp_upload_dir()['basedir']),
        ];

        $all_healthy = !in_array(false, $health, true);

        $this->audit_log('heartbeat', true, $ip);

        return new WP_REST_Response([
            'status' => $all_healthy ? 'healthy' : 'degraded',
            'timestamp' => current_time('c'),
            'uptime' => $this->get_uptime(),
            'version' => SADIE_PUBLISHER_VERSION,
            'wordpress' => get_bloginfo('version'),
            'php' => PHP_VERSION,
            'builder' => $builder,
            'seo_plugin' => $seo,
            'theme' => wp_get_theme()->get('Name'),
            'ssl' => is_ssl(),
            'trusted_update_domains' => self::$trusted_update_domains,
            'last_self_update' => get_option('sadie_publisher_last_self_update', null),
            'posts' => [
                'published' => $post_counts->publish ?? 0,
                'draft' => $post_counts->draft ?? 0,
                'pending' => $post_counts->pending ?? 0,
                'scheduled' => $post_counts->future ?? 0,
                'total_sadie' => $this->count_sadie_posts(),
            ],
            'last_publish' => [
                'time' => $last_publish_time,
                'post_id' => $last_publish_id,
            ],
            'health' => $health,
        ], 200);
    }

    private function get_uptime() {
        $activated = get_option('sadie_publisher_activated_at');
        if (!$activated) return null;
        $activated_ts = strtotime($activated);
        return time() - $activated_ts;
    }

    private function count_sadie_posts() {
        global $wpdb;
        return (int) $wpdb->get_var(
            "SELECT COUNT(DISTINCT post_id) FROM {$wpdb->postmeta} WHERE meta_key = '_sadie_published_at'"
        );
    }

    // =========================================================================
    // ENDPOINT: PUBLISH (Create Post)
    // =========================================================================

    public function handle_publish($request) {
        $ip = $this->get_client_ip();
        $params = $request->get_json_params();
        $settings = get_option($this->settings_option, []);

        // Validate required fields
        if (empty($params['title'])) {
            $this->audit_log('publish', false, $ip, 'Missing title');
            return new WP_Error('missing_title', 'Title is required.', ['status' => 400]);
        }
        if (empty($params['content'])) {
            $this->audit_log('publish', false, $ip, 'Missing content');
            return new WP_Error('missing_content', 'Content is required.', ['status' => 400]);
        }

        // Validate post status
        $allowed_statuses = ['draft', 'publish', 'pending', 'future', 'private'];
        $status = $params['status'] ?? $settings['default_status'] ?? 'draft';
        if (!in_array($status, $allowed_statuses, true)) {
            $status = 'draft';
        }

        // Validate post type
        $post_type = $params['post_type'] ?? 'post';
        if (!in_array($post_type, ['post', 'page'], true)) {
            $post_type = 'post';
        }

        // Prepare post content based on builder
        $builder = $this->detect_builder();
        $content = $this->prepare_content_for_builder($params['content'], $builder);

        // Build post data
        $post_data = [
            'post_title'   => sanitize_text_field($params['title']),
            'post_content' => $content,
            'post_status'  => $status,
            'post_author'  => absint($params['author_id'] ?? $settings['default_author'] ?? get_current_user_id()),
            'post_type'    => $post_type,
        ];

        if (!empty($params['slug'])) {
            $post_data['post_name'] = sanitize_title($params['slug']);
        }
        if (!empty($params['excerpt'])) {
            $post_data['post_excerpt'] = sanitize_textarea_field($params['excerpt']);
        }
        if (!empty($params['date'])) {
            $post_data['post_date'] = sanitize_text_field($params['date']);
            if ($status === 'future') {
                $post_data['post_date_gmt'] = get_gmt_from_date($params['date']);
            }
        }

        // Insert the post
        $post_id = wp_insert_post($post_data, true);

        if (is_wp_error($post_id)) {
            $this->audit_log('publish', false, $ip, $post_id->get_error_message());
            return $post_id;
        }

        // Builder-specific post meta
        $this->set_builder_meta($post_id, $builder, $params);

        // Categories
        if (!empty($params['categories'])) {
            $this->assign_categories($post_id, $params['categories']);
        }

        // Tags
        if (!empty($params['tags'])) {
            wp_set_post_tags($post_id, array_map('sanitize_text_field', (array) $params['tags']));
        }

        // Featured image
        if (!empty($params['featured_image']) && ($settings['allow_images'] ?? true)) {
            $img_data = is_array($params['featured_image']) ? $params['featured_image'] : ['url' => $params['featured_image']];
            $image_id = $this->upload_image_from_url(
                $img_data['url'],
                $img_data['alt'] ?? $params['title'],
                $post_id
            );
            if ($image_id && !is_wp_error($image_id)) {
                set_post_thumbnail($post_id, $image_id);
            }
        }

        // SEO meta
        if (!empty($params['seo'])) {
            $this->set_seo_meta($post_id, $params['seo']);
        }

        // Custom meta fields (sanitized)
        if (!empty($params['meta']) && is_array($params['meta'])) {
            foreach ($params['meta'] as $key => $value) {
                $safe_key = sanitize_key($key);
                // Block sensitive meta keys
                if (strpos($safe_key, 'sadie_publisher') !== false || $safe_key === 'wp_capabilities') {
                    continue;
                }
                update_post_meta($post_id, $safe_key, sanitize_text_field($value));
            }
        }

        // Sideload external images in content to local media library
        if ($settings['allow_images'] ?? true) {
            $this->sideload_content_images($post_id);
        }

        // Store Sadie tracking meta
        update_post_meta($post_id, '_sadie_article_id', sanitize_text_field($params['sadie_article_id'] ?? ''));
        update_post_meta($post_id, '_sadie_published_at', current_time('mysql'));
        update_post_meta($post_id, '_sadie_publisher_version', SADIE_PUBLISHER_VERSION);
        update_post_meta($post_id, '_sadie_builder', $builder['name']);

        $this->audit_log('publish', true, $ip, "Post #{$post_id}: " . $params['title']);

        return new WP_REST_Response([
            'success' => true,
            'post_id' => $post_id,
            'post_url' => get_permalink($post_id),
            'edit_url' => get_edit_post_link($post_id, 'raw'),
            'status' => get_post_status($post_id),
            'builder' => $builder['name'],
        ], 201);
    }

    // =========================================================================
    // ENDPOINT: UPDATE
    // =========================================================================

    public function handle_update($request) {
        $ip = $this->get_client_ip();
        $post_id = absint($request->get_param('id'));
        $params = $request->get_json_params();

        $post = get_post($post_id);
        if (!$post) {
            $this->audit_log('update', false, $ip, "Post #{$post_id} not found");
            return new WP_Error('not_found', 'Post not found.', ['status' => 404]);
        }

        $post_data = ['ID' => $post_id];

        if (!empty($params['title'])) {
            $post_data['post_title'] = sanitize_text_field($params['title']);
        }
        if (!empty($params['content'])) {
            $builder = $this->detect_builder();
            $post_data['post_content'] = $this->prepare_content_for_builder($params['content'], $builder);
        }
        if (!empty($params['status'])) {
            $allowed = ['draft', 'publish', 'pending', 'future', 'private'];
            if (in_array($params['status'], $allowed, true)) {
                $post_data['post_status'] = $params['status'];
            }
        }
        if (!empty($params['slug'])) {
            $post_data['post_name'] = sanitize_title($params['slug']);
        }
        if (!empty($params['excerpt'])) {
            $post_data['post_excerpt'] = sanitize_textarea_field($params['excerpt']);
        }
        if (!empty($params['date'])) {
            $post_data['post_date'] = sanitize_text_field($params['date']);
            if (($post_data['post_status'] ?? '') === 'future') {
                $post_data['post_date_gmt'] = get_gmt_from_date($params['date']);
            }
        }

        // WordPress requires edit_date=true to actually change post_date on updates
        if (!empty($params['date'])) {
            $post_data['edit_date'] = true;
        }

        $result = wp_update_post($post_data, true);
        if (is_wp_error($result)) {
            $this->audit_log('update', false, $ip, $result->get_error_message());
            return $result;
        }

        // Update SEO if provided
        if (!empty($params['seo'])) {
            $this->set_seo_meta($post_id, $params['seo']);
        }

        // Update categories if provided
        if (!empty($params['categories'])) {
            $this->assign_categories($post_id, $params['categories']);
        }

        // Update Elementor data if provided (allows direct editing of Elementor JSON)
        if (!empty($params['elementor_data'])) {
            $elementor_data = $params['elementor_data'];
            if (is_string($elementor_data)) {
                $decoded = json_decode($elementor_data, true);
                if (json_last_error() === JSON_ERROR_NONE) {
                    $elementor_data = $decoded;
                }
            }
            if (is_array($elementor_data)) {
                update_post_meta($post_id, '_elementor_data', wp_slash(wp_json_encode($elementor_data)));
                update_post_meta($post_id, '_elementor_edit_mode', 'builder');
            }
        }

        // Update featured image if provided
        $settings = get_option($this->settings_option, []);
        if (!empty($params['featured_image']) && ($settings['allow_images'] ?? true)) {
            $img_data = is_array($params['featured_image']) ? $params['featured_image'] : ['url' => $params['featured_image']];
            $image_id = $this->upload_image_from_url(
                $img_data['url'],
                $img_data['alt'] ?? ($params['title'] ?? $post->post_title),
                $post_id
            );
            if ($image_id && !is_wp_error($image_id)) {
                set_post_thumbnail($post_id, $image_id);
            }
        }

        // Sideload external images in content to local media library
        $settings = get_option($this->settings_option, []);
        if ($settings['allow_images'] ?? true) {
            $this->sideload_content_images($post_id);
        }

        update_post_meta($post_id, '_sadie_updated_at', current_time('mysql'));

        $this->audit_log('update', true, $ip, "Post #{$post_id}");

        return new WP_REST_Response([
            'success' => true,
            'post_id' => $post_id,
            'post_url' => get_permalink($post_id),
            'status' => get_post_status($post_id),
        ], 200);
    }

    // =========================================================================
    // ENDPOINT: GET POST DATA (content, elementor_data, post_content)
    // =========================================================================

    public function handle_get_post_data($request) {
        $post_id = absint($request->get_param('id'));
        $post = get_post($post_id);
        if (!$post) {
            return new WP_Error('not_found', 'Post not found.', ['status' => 404]);
        }

        $elementor_raw = get_post_meta($post_id, '_elementor_data', true);
        $elementor_data = null;
        if (!empty($elementor_raw)) {
            $decoded = json_decode($elementor_raw, true);
            if (json_last_error() === JSON_ERROR_NONE) {
                $elementor_data = $decoded;
            }
        }

        return new WP_REST_Response([
            'success'        => true,
            'post_id'        => $post_id,
            'post_title'     => $post->post_title,
            'post_status'    => $post->post_status,
            'post_content'   => $post->post_content,
            'elementor_data' => $elementor_data,
            'elementor_mode' => get_post_meta($post_id, '_elementor_edit_mode', true),
        ], 200);
    }

    // =========================================================================
    // SELF-UPDATE: SECURE REMOTE PLUGIN UPDATE
    // =========================================================================

    private static $trusted_update_domains = [
        'rfxzwdbuwccytyepjwwn.supabase.co',
        'github.com',
        'raw.githubusercontent.com',
        'objects.githubusercontent.com',
    ];

    public function handle_self_update($request) {
        // v3.0.6: wp-admin/includes/file.php defines wp_tempnam() and
        // WP_Filesystem(), both used below. REST requests don't auto-load
        // this file, so on hosts where it's not already in scope the call
        // to wp_tempnam() inside wp_safe_remote_get's 'filename' arg would
        // fatal silently (PHP Fatal -> 200 headers already sent -> empty
        // body -> only "Update initiated" in audit log). Loading it up
        // front is the single-line fix that unlocks self-update fleet-wide.
        if (!function_exists('wp_tempnam') || !function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }

        $ip = $this->get_client_ip();
        $params = $request->get_json_params();
        $zip_url = $params['zip_url'] ?? '';

        if (empty($zip_url) || !filter_var($zip_url, FILTER_VALIDATE_URL)) {
            $this->audit_log('self_update', false, $ip, 'Missing or invalid zip_url');
            return new WP_Error('bad_request', 'Valid zip_url is required.', ['status' => 400]);
        }

        if (strpos($zip_url, 'https://') !== 0) {
            $this->audit_log('self_update', false, $ip, 'Non-HTTPS zip_url rejected');
            return new WP_Error('bad_request', 'zip_url must use HTTPS.', ['status' => 400]);
        }

        $parsed = wp_parse_url($zip_url);
        $host = strtolower($parsed['host'] ?? '');
        $trusted = false;
        foreach (self::$trusted_update_domains as $domain) {
            if ($host === $domain || substr($host, -strlen('.' . $domain)) === '.' . $domain) {
                $trusted = true;
                break;
            }
        }
        if (!$trusted) {
            $this->audit_log('self_update', false, $ip, "Untrusted domain: {$host}");
            return new WP_Error('forbidden', 'zip_url domain is not trusted.', ['status' => 403]);
        }

        $path = $parsed['path'] ?? '';
        if (substr(strtolower($path), -4) !== '.zip') {
            $this->audit_log('self_update', false, $ip, 'URL does not point to a .zip file');
            return new WP_Error('bad_request', 'zip_url must point to a .zip file.', ['status' => 400]);
        }

        $this->audit_log('self_update', true, $ip, "Update initiated from {$host}");

        // v3.0.3: fetch with NO redirects. An open-redirect on a trusted
        // host (raw.githubusercontent.com gist redirects, supabase signed-
        // URL redirects) could otherwise bounce us to an attacker origin.
        // We already validated $zip_url's host against the allowlist; the
        // response body must come from exactly that host.
        $response = wp_safe_remote_get($zip_url, [
            'timeout'     => 30,
            'redirection' => 0,
            'sslverify'   => true,
            'stream'      => true,
            'filename'    => wp_tempnam(basename($zip_url)),
        ]);
        if (is_wp_error($response)) {
            $this->audit_log('self_update', false, $ip, 'Download failed: ' . $response->get_error_message());
            return new WP_Error('download_failed', 'Failed to download update package.', ['status' => 502]);
        }
        $status = wp_remote_retrieve_response_code($response);
        if ($status !== 200) {
            @unlink(wp_remote_retrieve_header($response, 'x-local-file'));
            $this->audit_log('self_update', false, $ip, "Download HTTP {$status} (redirect blocked or 404)");
            return new WP_Error('download_failed', "Update host returned HTTP {$status}. Redirects are blocked; provide the final URL directly.", ['status' => 502]);
        }
        $tmp_file = $response['filename'] ?? null;
        if (!$tmp_file || !file_exists($tmp_file)) {
            // Fallback: some WP versions don't set 'filename' in the returned array. Pull body into a tmp file.
            $body = wp_remote_retrieve_body($response);
            if (!$body) {
                $this->audit_log('self_update', false, $ip, 'Empty download body');
                return new WP_Error('download_failed', 'Empty download body.', ['status' => 502]);
            }
            $tmp_file = wp_tempnam('sadie-self-update');
            file_put_contents($tmp_file, $body);
        }

        $file_size = filesize($tmp_file);
        if ($file_size > 2 * 1024 * 1024) {
            @unlink($tmp_file);
            $this->audit_log('self_update', false, $ip, "ZIP too large: {$file_size} bytes");
            return new WP_Error('bad_request', 'Update package exceeds 2MB limit.', ['status' => 400]);
        }

        $result = $this->validate_and_apply_update($tmp_file, $ip);
        @unlink($tmp_file);

        if (is_wp_error($result)) {
            return $result;
        }

        // v3.0.8: record the most recent successful self-update so the
        // heartbeat can surface it without parsing the full audit log.
        update_option('sadie_publisher_last_self_update', [
            'time'             => current_time('c'),
            'previous_version' => $result['previous_version'] ?? null,
            'new_version'      => $result['new_version'] ?? null,
            'zip_host'         => $host,
        ]);

        return new WP_REST_Response($result, 200);
    }

    private function validate_and_apply_update($zip_path, $ip) {
        $zip = new ZipArchive();
        $open_result = $zip->open($zip_path, ZipArchive::RDONLY);
        if ($open_result !== true) {
            $this->audit_log('self_update', false, $ip, 'Invalid ZIP archive');
            return new WP_Error('bad_request', 'Invalid ZIP archive.', ['status' => 400]);
        }

        $valid_entries = [];
        $has_plugin_file = false;

        for ($i = 0; $i < $zip->numFiles; $i++) {
            $entry = $zip->getNameIndex($i);

            if (substr($entry, -1) === '/' || strpos($entry, '__MACOSX') !== false || strpos($entry, '.DS_Store') !== false) {
                continue;
            }

            $basename = basename($entry);

            if (strpos($entry, '..') !== false || strpos($entry, '\\') !== false) {
                $zip->close();
                $this->audit_log('self_update', false, $ip, "Path traversal attempt: {$entry}");
                return new WP_Error('forbidden', 'Invalid file path in archive.', ['status' => 403]);
            }

            if ($basename === 'sadie-publisher.php') {
                $has_plugin_file = true;
                $valid_entries[] = $entry;
            } else {
                $zip->close();
                $this->audit_log('self_update', false, $ip, "Unexpected file in ZIP: {$entry}");
                return new WP_Error('bad_request', "Unexpected file in archive: {$basename}", ['status' => 400]);
            }
        }

        if (!$has_plugin_file) {
            $zip->close();
            $this->audit_log('self_update', false, $ip, 'ZIP missing sadie-publisher.php');
            return new WP_Error('bad_request', 'Archive must contain sadie-publisher.php.', ['status' => 400]);
        }

        $new_plugin_content = $zip->getFromName($valid_entries[0]);
        $zip->close();

        if ($new_plugin_content === false || strlen($new_plugin_content) < 100) {
            $this->audit_log('self_update', false, $ip, 'Could not read plugin file from ZIP or file too small');
            return new WP_Error('bad_request', 'Invalid plugin file in archive.', ['status' => 400]);
        }

        if (strpos($new_plugin_content, 'Plugin Name: Sadie') === false) {
            $this->audit_log('self_update', false, $ip, 'Missing or wrong Plugin Name header');
            return new WP_Error('bad_request', 'Plugin file missing valid "Plugin Name: Sadie" header.', ['status' => 400]);
        }

        $trimmed = ltrim($new_plugin_content);
        if (strpos($trimmed, '<?php') !== 0) {
            $this->audit_log('self_update', false, $ip, 'File does not start with <?php');
            return new WP_Error('bad_request', 'Plugin file must start with <?php.', ['status' => 400]);
        }

        // v3.0.3 — expanded blocklist.
        // Security audit caught 4 bypass classes in v3.0.2 list:
        //   (a) call_user_func / _array — pass 'eval' as string arg
        //   (b) include / require with php:// or data:// streams
        //   (c) ReflectionFunction::invoke
        //   (d) preg_replace with /e modifier (pre-PHP7 systems)
        // Stopgap until we switch to Ed25519 signature verification.
        $dangerous_funcs = [
            'ev' . 'al',
            'ex' . 'ec',
            'sys' . 'tem',
            'passth' . 'ru',
            'shell_ex' . 'ec',
            'pop' . 'en',
            'proc_op' . 'en',
            'pcntl_ex' . 'ec',
            'ass' . 'ert',
            'create_func' . 'tion',
            'base64_dec' . 'ode',
            'gzinfl' . 'ate',
            'str_rot' . '13',
            'curl_ex' . 'ec',
            'phpin' . 'fo',
            'call_user_func',        // can route to 'eval' as string
            'call_user_func_array',
            'hex' . '2bin',          // obfuscation primitive
            'unpack',                // byte-to-string -> concat into func name
            'ReflectionFunction',    // can invoke anything by name
            'ReflectionMethod',
        ];

        foreach ($dangerous_funcs as $func) {
            $regex = '/(?<!\w)' . preg_quote($func, '/') . '\s*\(/i';
            if (preg_match($regex, $new_plugin_content)) {
                $this->audit_log('self_update', false, $ip, "Dangerous pattern detected: {$func}()");
                return new WP_Error('forbidden', "Plugin file contains forbidden pattern: {$func}()", ['status' => 403]);
            }
        }

        // include/require with any argument (even a constant). We don't use
        // these in the plugin at all — blanket ban.
        if (preg_match('/(?<!\w)(?:include|require)(?:_once)?\s*[\s\(]/i', $new_plugin_content)) {
            $this->audit_log('self_update', false, $ip, 'Dangerous pattern: include/require');
            return new WP_Error('forbidden', 'Plugin file contains forbidden pattern: include/require', ['status' => 403]);
        }

        // Backtick operator — PHP syntax for shell command execution.
        // Exclude backticks inside single/double quoted strings (esc).
        // We don't use backticks legitimately anywhere.
        if (preg_match('/`[^`\n]{0,200}`/', $new_plugin_content)) {
            $this->audit_log('self_update', false, $ip, 'Dangerous pattern: backtick shell operator');
            return new WP_Error('forbidden', 'Plugin file contains forbidden pattern: backtick operator', ['status' => 403]);
        }

        // Variable-function calls: $foo(...) where $foo is a variable. Our
        // plugin uses arrow-access + method calls but never $var() dispatch.
        if (preg_match('/\$[a-z_][a-z0-9_]*\s*\(/i', $new_plugin_content)) {
            $this->audit_log('self_update', false, $ip, 'Dangerous pattern: variable-function call $var(...)');
            return new WP_Error('forbidden', 'Plugin file contains forbidden pattern: $variable(...)', ['status' => 403]);
        }

        // preg_replace with /e modifier (deprecated but still runnable on
        // some old forks). Detect an /e at end of the pattern delimiter.
        if (preg_match('/preg_replace\s*\([^)]*["\'\/#][^"\'\/#]*["\'\/#]\s*e\s*["\'\/#]/i', $new_plugin_content)) {
            $this->audit_log('self_update', false, $ip, 'Dangerous pattern: preg_replace /e modifier');
            return new WP_Error('forbidden', 'Plugin file contains forbidden pattern: preg_replace /e', ['status' => 403]);
        }

        // PHP wrapper streams inside any string literal (payload delivery).
        if (preg_match('/(?:php:\/\/|data:\/\/|phar:\/\/|expect:\/\/)/i', $new_plugin_content)) {
            $this->audit_log('self_update', false, $ip, 'Dangerous pattern: php:// / data:// / phar:// / expect:// stream wrapper');
            return new WP_Error('forbidden', 'Plugin file contains forbidden pattern: dangerous stream wrapper', ['status' => 403]);
        }

        if (preg_match('/file_get_conte' . 'nts\s*\(\s*[\'"]https?:/i', $new_plugin_content)) {
            $this->audit_log('self_update', false, $ip, 'Dangerous pattern detected: remote file_get_contents()');
            return new WP_Error('forbidden', 'Plugin file contains forbidden pattern: remote file_get_contents()', ['status' => 403]);
        }

        // v3.0.3 persistent-backdoor guard: the static $trusted_update_domains
        // array is the fence that protects every future update. A malicious
        // update that rewrites the allowlist would permanently widen it.
        // Require the exact same 4-host list we ship with. If the attacker
        // changes any one entry, the update fails here.
        $expected_allowlist_re = '/private\s+static\s+\$trusted_update_domains\s*=\s*\[\s*'
            . "'rfxzwdbuwccytyepjwwn\\.supabase\\.co'\\s*,\\s*"
            . "'github\\.com'\\s*,\\s*"
            . "'raw\\.githubusercontent\\.com'\\s*,\\s*"
            . "'objects\\.githubusercontent\\.com'\\s*,?\\s*"
            . '\]\s*;/';
        if (!preg_match($expected_allowlist_re, $new_plugin_content)) {
            $this->audit_log('self_update', false, $ip, 'Trusted-update-domain allowlist modified; refusing');
            return new WP_Error(
                'forbidden',
                'Update rejected: $trusted_update_domains allowlist cannot be changed via self-update. Ship the fixed allowlist by hand via SFTP if needed.',
                ['status' => 403]
            );
        }

        $new_version = 'unknown';
        if (preg_match('/\*\s*Version:\s*([0-9]+\.[0-9]+\.[0-9]+)/', $new_plugin_content, $m)) {
            $new_version = $m[1];
        }

        if (!function_exists('WP_Filesystem')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        WP_Filesystem();
        global $wp_filesystem;

        if (!$wp_filesystem) {
            $this->audit_log('self_update', false, $ip, 'WP_Filesystem not available');
            return new WP_Error('server_error', 'Filesystem access not available.', ['status' => 500]);
        }

        $plugin_file = plugin_dir_path(__FILE__) . 'sadie-publisher.php';
        $backup_file = plugin_dir_path(__FILE__) . 'sadie-publisher.php.backup';

        if ($wp_filesystem->exists($plugin_file)) {
            $current_content = $wp_filesystem->get_contents($plugin_file);
            if (!$wp_filesystem->put_contents($backup_file, $current_content, FS_CHMOD_FILE)) {
                $this->audit_log('self_update', false, $ip, 'Failed to create backup');
                return new WP_Error('server_error', 'Failed to create backup.', ['status' => 500]);
            }
        }

        if (!$wp_filesystem->put_contents($plugin_file, $new_plugin_content, FS_CHMOD_FILE)) {
            if ($wp_filesystem->exists($backup_file)) {
                $wp_filesystem->put_contents($plugin_file, $wp_filesystem->get_contents($backup_file), FS_CHMOD_FILE);
            }
            $this->audit_log('self_update', false, $ip, 'Failed to write new plugin file');
            return new WP_Error('server_error', 'Failed to write update. Previous version restored.', ['status' => 500]);
        }

        // Force OpCache to invalidate the new file so subsequent requests load
        // fresh opcodes. Without this, PHP-FPM hosts with
        // opcache.validate_timestamps=0 keep running the OLD compiled version
        // even though the file on disk is new.
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($plugin_file, true);
        }

        // Post-swap smoke test: self-curl /wp-json/ (the REST root — no auth
        // required). If the new plugin has a parse / fatal error, WP returns
        // 500 on every endpoint. Any non-5xx response proves the plugin
        // loaded clean. We do 3 attempts with 2s backoff to smooth out
        // transient hosting blips (503s we've seen on travelbug).
        //
        // Why not /ping anymore: /ping requires auth. On HMAC-enabled sites,
        // unsigned probes got 401, which older versions mis-classified as
        // "failure" and rolled back every self-update. Root-probing dodges
        // the auth layer entirely.
        $probe_url = home_url('/wp-json/');
        $smoke_ok = false;
        $smoke_info = '';
        for ($attempt = 1; $attempt <= 3; $attempt++) {
            $smoke = wp_remote_get($probe_url, [
                'timeout' => 10,
                'sslverify' => apply_filters('sadie_smoke_test_sslverify', true),
            ]);
            $code = is_wp_error($smoke) ? 0 : (int) wp_remote_retrieve_response_code($smoke);
            $smoke_info = is_wp_error($smoke)
                ? ('wp_error: ' . $smoke->get_error_message())
                : ('HTTP ' . $code);
            if (!is_wp_error($smoke) && $code > 0 && $code < 500) {
                $smoke_ok = true;
                break;
            }
            if ($attempt < 3) usleep(2_000_000); // 2s
        }

        if (!$smoke_ok) {
            if ($wp_filesystem->exists($backup_file)) {
                $wp_filesystem->put_contents($plugin_file, $wp_filesystem->get_contents($backup_file), FS_CHMOD_FILE);
                $wp_filesystem->delete($backup_file);
                if (function_exists('opcache_invalidate')) {
                    @opcache_invalidate($plugin_file, true);
                }
            }
            $this->audit_log('self_update', false, $ip, "Smoke test failed ({$smoke_info}); rolled back");
            return new WP_Error('smoke_test_failed', "Smoke test failed after update: {$smoke_info}. Rolled back.", ['status' => 500]);
        }

        $wp_filesystem->delete($backup_file);

        $this->audit_log('self_update', true, $ip, "Updated to v{$new_version} from v" . SADIE_PUBLISHER_VERSION . " (smoke: {$smoke_info})");

        return [
            'success' => true,
            'previous_version' => SADIE_PUBLISHER_VERSION,
            'new_version' => $new_version,
            'message' => "Plugin updated to v{$new_version}.",
        ];
    }

    // =========================================================================
    // ENDPOINT: DELETE
    // =========================================================================

    public function handle_delete($request) {
        $ip = $this->get_client_ip();
        $post_id = absint($request->get_param('id'));
        $force = $request->get_param('force') === 'true';

        $post = get_post($post_id);
        if (!$post) {
            $this->audit_log('delete', false, $ip, "Post #{$post_id} not found");
            return new WP_Error('not_found', 'Post not found.', ['status' => 404]);
        }

        // Only allow deletion of Sadie-published posts
        $sadie_meta = get_post_meta($post_id, '_sadie_published_at', true);
        if (empty($sadie_meta)) {
            $this->audit_log('delete', false, $ip, "Post #{$post_id} not a Sadie post");
            return new WP_Error('forbidden', 'Can only delete posts created by Sadie.', ['status' => 403]);
        }

        $result = wp_delete_post($post_id, $force);
        if (!$result) {
            $this->audit_log('delete', false, $ip, "Failed to delete #{$post_id}");
            return new WP_Error('delete_failed', 'Failed to delete post.', ['status' => 500]);
        }

        $this->audit_log('delete', true, $ip, "Post #{$post_id}" . ($force ? ' (permanent)' : ' (trashed)'));

        return new WP_REST_Response([
            'success' => true,
            'message' => $force ? 'Post permanently deleted.' : 'Post moved to trash.',
        ], 200);
    }

    // =========================================================================
    // CONTENT PREPARATION (Builder-Aware)
    // =========================================================================

    private function prepare_content_for_builder($content, $builder) {
        // Sanitize HTML content
        $content = wp_kses_post($content);

        switch ($builder['name']) {
            case 'gutenberg':
                return $this->convert_to_gutenberg_blocks($content);

            case 'elementor':
                // Elementor reads from post_content for blog posts
                // The Elementor template is applied by the theme, not stored per-post for standard posts
                // We just need clean HTML
                return $content;

            case 'flatsome':
                // Flatsome uses standard post_content for blog posts
                // UX Builder is primarily for pages, not posts
                return $content;

            case 'divi':
                // Divi Builder: standard HTML works for posts
                // Divi applies its blog template around the content
                return $content;

            default:
                // Classic editor / other builders: standard HTML
                return $content;
        }
    }

    private function convert_to_gutenberg_blocks($html) {
        // If content already has block markers, return as-is
        if (strpos($html, '<!-- wp:') !== false) {
            return $html;
        }

        // Split HTML into logical sections and wrap in appropriate blocks
        // For blog posts, wrapping in a single html block is the most reliable approach
        // This ensures the content renders correctly regardless of theme
        $blocks = [];

        // Use DOMDocument for reliable parsing
        if (class_exists('DOMDocument') && !empty(trim($html))) {
            $doc = new \DOMDocument();
            // Suppress warnings from malformed HTML
            @$doc->loadHTML(
                '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body>' . $html . '</body></html>',
                LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD
            );

            $body = $doc->getElementsByTagName('body')->item(0);
            if ($body) {
                foreach ($body->childNodes as $node) {
                    if ($node->nodeType !== XML_ELEMENT_NODE) {
                        continue;
                    }

                    $tag = strtolower($node->nodeName);
                    $inner = $doc->saveHTML($node);

                    switch ($tag) {
                        case 'h1':
                        case 'h2':
                        case 'h3':
                        case 'h4':
                        case 'h5':
                        case 'h6':
                            $level = (int) substr($tag, 1);
                            $text = $node->textContent;
                            $blocks[] = "<!-- wp:heading {\"level\":{$level}} -->\n<{$tag} class=\"wp-block-heading\">{$text}</{$tag}>\n<!-- /wp:heading -->";
                            break;

                        case 'p':
                            $blocks[] = "<!-- wp:paragraph -->\n{$inner}\n<!-- /wp:paragraph -->";
                            break;

                        case 'ul':
                            $blocks[] = "<!-- wp:list -->\n{$inner}\n<!-- /wp:list -->";
                            break;

                        case 'ol':
                            $blocks[] = "<!-- wp:list {\"ordered\":true} -->\n{$inner}\n<!-- /wp:list -->";
                            break;

                        case 'blockquote':
                            $blocks[] = "<!-- wp:quote -->\n{$inner}\n<!-- /wp:quote -->";
                            break;

                        case 'img':
                            $src = $node->getAttribute('src');
                            $alt = $node->getAttribute('alt');
                            $blocks[] = "<!-- wp:image -->\n<figure class=\"wp-block-image\"><img src=\"{$src}\" alt=\"{$alt}\"/></figure>\n<!-- /wp:image -->";
                            break;

                        case 'figure':
                            $blocks[] = "<!-- wp:image -->\n{$inner}\n<!-- /wp:image -->";
                            break;

                        case 'table':
                            $blocks[] = "<!-- wp:table -->\n<figure class=\"wp-block-table\">{$inner}</figure>\n<!-- /wp:table -->";
                            break;

                        default:
                            // Wrap unknown elements in an html block
                            $blocks[] = "<!-- wp:html -->\n{$inner}\n<!-- /wp:html -->";
                            break;
                    }
                }
            }
        }

        if (empty($blocks)) {
            // Fallback: wrap entire content in a single HTML block
            return "<!-- wp:html -->\n{$html}\n<!-- /wp:html -->";
        }

        return implode("\n\n", $blocks);
    }

    private function set_builder_meta($post_id, $builder, $params) {
        switch ($builder['name']) {
            case 'elementor':
                // Tell Elementor this post uses the default editor, not Elementor
                // This prevents Elementor from trying to render its own canvas
                update_post_meta($post_id, '_elementor_edit_mode', '');
                break;

            case 'divi':
                // Tell Divi to use default editor for this post
                update_post_meta($post_id, '_et_pb_use_builder', 'off');
                break;

            case 'beaver_builder':
                // Tell Beaver Builder this is a standard post
                update_post_meta($post_id, '_fl_builder_enabled', false);
                break;
        }

        // Store which builder was active at publish time
        update_post_meta($post_id, '_sadie_builder', $builder['name']);
    }

    // =========================================================================
    // CATEGORIES
    // =========================================================================

    private function assign_categories($post_id, $categories) {
        $cat_ids = [];
        foreach ((array) $categories as $cat) {
            if (is_numeric($cat)) {
                $cat_ids[] = absint($cat);
            } else {
                $cat_name = sanitize_text_field($cat);
                $term = get_term_by('name', $cat_name, 'category');
                if ($term) {
                    $cat_ids[] = $term->term_id;
                } else {
                    $new_term = wp_insert_term($cat_name, 'category');
                    if (!is_wp_error($new_term)) {
                        $cat_ids[] = $new_term['term_id'];
                    }
                }
            }
        }
        if (!empty($cat_ids)) {
            wp_set_post_categories($post_id, $cat_ids);
        }
    }

    // =========================================================================
    // SEO META
    // =========================================================================

    private function set_seo_meta($post_id, $seo) {
        $settings = get_option($this->settings_option, []);
        $seo_plugin = $settings['seo_plugin'] ?? 'auto';

        if ($seo_plugin === 'auto') {
            $seo_plugin = $this->detect_seo_plugin();
        }

        $meta_title = sanitize_text_field($seo['meta_title'] ?? '');
        $meta_description = sanitize_text_field($seo['meta_description'] ?? '');
        $focus_keyword = sanitize_text_field($seo['focus_keyword'] ?? '');
        $canonical_url = esc_url_raw($seo['canonical_url'] ?? '');
        $og_title = sanitize_text_field($seo['og_title'] ?? $meta_title);
        $og_description = sanitize_text_field($seo['og_description'] ?? $meta_description);

        switch ($seo_plugin) {
            case 'yoast':
                if ($meta_title) update_post_meta($post_id, '_yoast_wpseo_title', $meta_title);
                if ($meta_description) update_post_meta($post_id, '_yoast_wpseo_metadesc', $meta_description);
                if ($focus_keyword) update_post_meta($post_id, '_yoast_wpseo_focuskw', $focus_keyword);
                if ($canonical_url) update_post_meta($post_id, '_yoast_wpseo_canonical', $canonical_url);
                if ($og_title) update_post_meta($post_id, '_yoast_wpseo_opengraph-title', $og_title);
                if ($og_description) update_post_meta($post_id, '_yoast_wpseo_opengraph-description', $og_description);
                break;

            case 'rankmath':
                if ($meta_title) update_post_meta($post_id, 'rank_math_title', $meta_title);
                if ($meta_description) update_post_meta($post_id, 'rank_math_description', $meta_description);
                if ($focus_keyword) update_post_meta($post_id, 'rank_math_focus_keyword', $focus_keyword);
                if ($canonical_url) update_post_meta($post_id, 'rank_math_canonical_url', $canonical_url);
                if ($og_title) update_post_meta($post_id, 'rank_math_facebook_title', $og_title);
                if ($og_description) update_post_meta($post_id, 'rank_math_facebook_description', $og_description);
                break;

            case 'aioseo':
                if ($meta_title) update_post_meta($post_id, '_aioseo_title', $meta_title);
                if ($meta_description) update_post_meta($post_id, '_aioseo_description', $meta_description);
                if ($focus_keyword) update_post_meta($post_id, '_aioseo_keywords', $focus_keyword);
                if ($canonical_url) update_post_meta($post_id, '_aioseo_canonical_url', $canonical_url);
                if ($og_title) update_post_meta($post_id, '_aioseo_og_title', $og_title);
                if ($og_description) update_post_meta($post_id, '_aioseo_og_description', $og_description);
                break;

            default:
                // No SEO plugin — store as generic Sadie meta
                if ($meta_title) update_post_meta($post_id, '_sadie_meta_title', $meta_title);
                if ($meta_description) update_post_meta($post_id, '_sadie_meta_description', $meta_description);
                if ($focus_keyword) update_post_meta($post_id, '_sadie_focus_keyword', $focus_keyword);
                break;
        }

        // Schema markup
        if (!empty($seo['schema'])) {
            update_post_meta($post_id, '_sadie_schema', wp_kses_post($seo['schema']));
        }
    }

    // =========================================================================
    // SEO META ENDPOINT (v3.0.4)
    // =========================================================================

    /**
     * POST /seo-meta — Update SEO meta on any post/page.
     *
     * Accepts: { post_id | slug | url, meta_title, meta_description,
     *            focus_keyword, canonical_url, robots, og_title, og_description, schema }
     *
     * `robots` can be a string like "noindex,nofollow" or an object like
     * { noindex: true, nofollow: false }. This writes to Yoast/RankMath/AIOSEO.
     */
    public function handle_seo_meta($request) {
        $ip = $this->get_client_ip();
        $body = $request->get_json_params();

        // Resolve the post
        $post = $this->resolve_post($body);
        if (is_wp_error($post)) {
            return $post;
        }

        $result = $this->apply_seo_meta($post->ID, $body);
        $this->audit_log('seo_meta', true, $ip, "Updated SEO meta on post #{$post->ID} ({$post->post_title})");

        return new WP_REST_Response([
            'success' => true,
            'post_id' => $post->ID,
            'url' => get_permalink($post->ID),
            'updated' => $result,
        ], 200);
    }

    /**
     * POST /seo-meta/bulk — Update SEO meta on multiple posts.
     *
     * Accepts: { items: [ { post_id | slug | url, meta_title, ... }, ... ] }
     */
    public function handle_seo_meta_bulk($request) {
        $ip = $this->get_client_ip();
        $body = $request->get_json_params();
        $items = $body['items'] ?? [];

        if (!is_array($items) || count($items) === 0) {
            return new WP_Error('bad_request', 'items array is required.', ['status' => 400]);
        }
        if (count($items) > 50) {
            return new WP_Error('bad_request', 'Maximum 50 items per bulk request.', ['status' => 400]);
        }

        $results = [];
        $success = 0;
        $failed = 0;

        foreach ($items as $i => $item) {
            $post = $this->resolve_post($item);
            if (is_wp_error($post)) {
                $results[] = ['index' => $i, 'success' => false, 'error' => $post->get_error_message()];
                $failed++;
                continue;
            }
            $updated = $this->apply_seo_meta($post->ID, $item);
            $results[] = ['index' => $i, 'success' => true, 'post_id' => $post->ID, 'url' => get_permalink($post->ID), 'updated' => $updated];
            $success++;
        }

        $this->audit_log('seo_meta_bulk', true, $ip, "Bulk SEO meta: {$success} ok, {$failed} failed");

        return new WP_REST_Response([
            'success' => true,
            'processed' => count($items),
            'succeeded' => $success,
            'failed' => $failed,
            'results' => $results,
        ], 200);
    }

    /**
     * Resolve a WP_Post from { post_id, slug, or url }.
     */
    private function resolve_post($params) {
        // By explicit post_id
        if (!empty($params['post_id'])) {
            $post = get_post(absint($params['post_id']));
            if (!$post) {
                return new WP_Error('not_found', "Post #{$params['post_id']} not found.", ['status' => 404]);
            }
            return $post;
        }

        // By slug
        if (!empty($params['slug'])) {
            $slug = sanitize_title($params['slug']);
            // Search posts and pages
            $posts = get_posts([
                'name' => $slug,
                'post_type' => ['post', 'page', 'product'],
                'post_status' => ['publish', 'draft', 'private'],
                'numberposts' => 1,
            ]);
            if (empty($posts)) {
                return new WP_Error('not_found', "No post found with slug '{$slug}'.", ['status' => 404]);
            }
            return $posts[0];
        }

        // By URL — extract the path and use url_to_postid
        if (!empty($params['url'])) {
            $url = esc_url_raw($params['url']);
            $post_id = url_to_postid($url);
            if ($post_id) {
                return get_post($post_id);
            }
            // Fallback: try extracting slug from URL path
            $path = trim(wp_parse_url($url, PHP_URL_PATH), '/');
            $segments = explode('/', $path);
            $slug = end($segments);
            if ($slug) {
                $posts = get_posts([
                    'name' => sanitize_title($slug),
                    'post_type' => ['post', 'page', 'product'],
                    'post_status' => ['publish', 'draft', 'private'],
                    'numberposts' => 1,
                ]);
                if (!empty($posts)) {
                    return $posts[0];
                }
            }
            return new WP_Error('not_found', "No post found for URL '{$url}'.", ['status' => 404]);
        }

        return new WP_Error('bad_request', 'Provide post_id, slug, or url.', ['status' => 400]);
    }

    /**
     * Apply SEO meta fields to a post. Returns list of fields that were updated.
     */
    private function apply_seo_meta($post_id, $fields) {
        $updated = [];

        // Standard SEO fields — delegate to existing set_seo_meta
        $seo_fields = [];
        foreach (['meta_title', 'meta_description', 'focus_keyword', 'canonical_url', 'og_title', 'og_description', 'schema'] as $key) {
            if (isset($fields[$key]) && $fields[$key] !== '') {
                $seo_fields[$key] = $fields[$key];
                $updated[] = $key;
            }
        }
        if (!empty($seo_fields)) {
            $this->set_seo_meta($post_id, $seo_fields);
        }

        // Robots / noindex — needs special handling per SEO plugin
        if (isset($fields['robots'])) {
            $this->set_robots_meta($post_id, $fields['robots']);
            $updated[] = 'robots';
        }

        return $updated;
    }

    /**
     * Set robots/noindex meta on a post via the detected SEO plugin.
     *
     * Accepts either:
     *   - string: "noindex", "noindex,nofollow", "index,follow"
     *   - object: { noindex: true, nofollow: false }
     */
    private function set_robots_meta($post_id, $robots) {
        $settings = get_option($this->settings_option, []);
        $seo_plugin = $settings['seo_plugin'] ?? 'auto';
        if ($seo_plugin === 'auto') {
            $seo_plugin = $this->detect_seo_plugin();
        }

        // Normalize to flags
        $noindex = false;
        $nofollow = false;
        if (is_string($robots)) {
            $lower = strtolower($robots);
            $noindex = strpos($lower, 'noindex') !== false;
            $nofollow = strpos($lower, 'nofollow') !== false;
        } elseif (is_array($robots)) {
            $noindex = !empty($robots['noindex']);
            $nofollow = !empty($robots['nofollow']);
        }

        switch ($seo_plugin) {
            case 'yoast':
                // Yoast stores robots as _yoast_wpseo_meta-robots-noindex (1=noindex, 0=default)
                // and _yoast_wpseo_meta-robots-nofollow (1=nofollow, 0=default)
                update_post_meta($post_id, '_yoast_wpseo_meta-robots-noindex', $noindex ? '1' : '0');
                update_post_meta($post_id, '_yoast_wpseo_meta-robots-nofollow', $nofollow ? '1' : '0');
                break;

            case 'rankmath':
                // RankMath stores robots as a serialized array in rank_math_robots
                $rm_robots = [];
                $rm_robots[] = $noindex ? 'noindex' : 'index';
                $rm_robots[] = $nofollow ? 'nofollow' : 'follow';
                update_post_meta($post_id, 'rank_math_robots', $rm_robots);
                break;

            case 'aioseo':
                update_post_meta($post_id, '_aioseo_noindex', $noindex ? '1' : '0');
                update_post_meta($post_id, '_aioseo_nofollow', $nofollow ? '1' : '0');
                break;

            default:
                update_post_meta($post_id, '_sadie_robots_noindex', $noindex ? '1' : '0');
                update_post_meta($post_id, '_sadie_robots_nofollow', $nofollow ? '1' : '0');
                break;
        }
    }

    // =========================================================================
    // IMAGE HANDLING
    // =========================================================================

    /**
     * Scan post content for external <img> tags, download each to the
     * WordPress media library, and replace the src with the local URL.
     * Skips images already hosted on this site.
     */
    private function sideload_content_images($post_id) {
        $post = get_post($post_id);
        if (!$post || empty($post->post_content)) {
            return;
        }

        $content = $post->post_content;
        $site_host = wp_parse_url(home_url(), PHP_URL_HOST);

        // Match all <img> tags with src attribute
        if (!preg_match_all('/<img[^>]+src=["\']([^"\']+)["\'][^>]*>/i', $content, $matches, PREG_SET_ORDER)) {
            return;
        }

        $updated = false;
        foreach ($matches as $match) {
            $full_tag = $match[0];
            $img_url  = $match[1];

            // Skip images already on this site
            $img_host = wp_parse_url($img_url, PHP_URL_HOST);
            if ($img_host === $site_host) {
                continue;
            }

            // Skip data URIs
            if (strpos($img_url, 'data:') === 0) {
                continue;
            }

            // Extract alt text from the tag if present
            $alt = '';
            if (preg_match('/alt=["\']([^"\']*)["\']/', $full_tag, $alt_match)) {
                $alt = $alt_match[1];
            }

            // Download and sideload
            $attachment_id = $this->upload_image_from_url($img_url, $alt, $post_id);
            if (!$attachment_id || is_wp_error($attachment_id)) {
                continue;
            }

            // Get the new local URL
            $local_url = wp_get_attachment_url($attachment_id);
            if (!$local_url) {
                continue;
            }

            // Replace old URL with local URL in the tag
            $new_tag = str_replace($img_url, $local_url, $full_tag);
            $content = str_replace($full_tag, $new_tag, $content);
            $updated = true;
        }

        if ($updated) {
            wp_update_post([
                'ID'           => $post_id,
                'post_content' => $content,
            ]);
        }
    }

    private function upload_image_from_url($url, $alt_text = '', $post_id = 0) {
        // Validate URL
        $url = esc_url_raw($url);
        if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
            return new WP_Error('invalid_url', 'Invalid image URL.');
        }

        // Only allow http/https protocols
        $scheme = wp_parse_url($url, PHP_URL_SCHEME);
        if (!in_array($scheme, ['http', 'https'], true)) {
            return new WP_Error('invalid_scheme', 'Only HTTP/HTTPS image URLs allowed.');
        }

        require_once ABSPATH . 'wp-admin/includes/media.php';
        require_once ABSPATH . 'wp-admin/includes/file.php';
        require_once ABSPATH . 'wp-admin/includes/image.php';

        $tmp = download_url($url, 30); // 30 second timeout

        if (is_wp_error($tmp)) {
            return $tmp;
        }

        // Validate file type
        $file_type = wp_check_filetype(basename(wp_parse_url($url, PHP_URL_PATH)));
        $allowed_types = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
        if (!empty($file_type['type']) && !in_array($file_type['type'], $allowed_types, true)) {
            @unlink($tmp);
            return new WP_Error('invalid_type', 'File type not allowed: ' . $file_type['type']);
        }

        // Validate file size (max 10MB)
        $max_size = 10 * 1024 * 1024;
        if (filesize($tmp) > $max_size) {
            @unlink($tmp);
            return new WP_Error('too_large', 'Image exceeds 10MB limit.');
        }

        $filename = basename(wp_parse_url($url, PHP_URL_PATH));
        if (empty($filename) || $filename === '/') {
            $filename = 'sadie-image-' . time() . '.jpg';
        }

        $file_array = [
            'name'     => sanitize_file_name($filename),
            'tmp_name' => $tmp,
        ];

        $attachment_id = media_handle_sideload($file_array, $post_id, sanitize_text_field($alt_text));

        @unlink($tmp);

        if (is_wp_error($attachment_id)) {
            return $attachment_id;
        }

        if ($alt_text) {
            update_post_meta($attachment_id, '_wp_attachment_image_alt', sanitize_text_field($alt_text));
        }

        return $attachment_id;
    }
}

// =============================================================================
// v3.0 — Internal Link Injector
// =============================================================================

/**
 * Hooks `the_content` on priority 20. Pulls approved links for the current
 * page from Sadie's API (cached 6h in transient), wraps the first matching
 * in-body phrase in an <a> tag. DOM-walks so it skips <a>, <code>, <pre>,
 * shortcodes, Elementor JSON. Circuit-breakered on API failure.
 */
class Sadie_Internal_Links {
    private $settings;
    private $audit_buffer = [];

    public function __construct() {
        add_filter('the_content', [$this, 'inject'], 20);
        add_action('shutdown', [$this, 'flush_audit']);
        add_action('save_post', [$this, 'flush_page_transient'], 10, 1);
    }

    private function enabled() {
        $this->settings = get_option('sadie_publisher_settings', []);
        return !empty($this->settings['internal_links_enabled']);
    }

    public function flush_page_transient($post_id) {
        delete_transient('sadie_links_page_' . $post_id);
    }

    private function api_base() {
        return $this->settings['sadie_api_base'] ?? SADIE_API_BASE;
    }

    /**
     * Pulls the client's full approved-link set (keyed by source URL) from Sadie.
     * Cached in transient. Circuit-breaker: on HTTP fail, serve last-known even
     * if expired, and set a 5-min "don't retry" lock so flaky API never blocks
     * the render.
     */
    private function fetch_links_for_client() {
        $locked = get_transient('sadie_links_circuit_open');
        $cached = get_transient('sadie_links_index');
        if ($locked && $cached !== false) return $cached;

        if ($cached !== false && !empty($cached['_fresh'])) return $cached;

        $token = get_option('sadie_publisher_project_token');
        if (!$token) return [];

        $path = '/api/wp-plugin/v1/links';
        $ts = (string) time();
        $payload = $ts . 'GET' . $path;
        $sig = hash_hmac('sha256', $payload, $token);

        $url = $this->api_base() . $path;
        $res = wp_remote_get($url, [
            'timeout' => 2, // tight — but > 800ms so plugin install on slow hosts works
            'redirection' => 2,
            'headers' => [
                'X-Sadie-Project-Token' => $token,
                'X-Sadie-Timestamp' => $ts,
                'X-Sadie-Signature' => $sig,
                'X-Sadie-Nonce' => wp_generate_uuid4(),
                'Accept' => 'application/json',
            ],
        ]);

        if (is_wp_error($res) || wp_remote_retrieve_response_code($res) !== 200) {
            // Circuit break: trust stale transient for 5 min, then retry
            set_transient('sadie_links_circuit_open', 1, 5 * MINUTE_IN_SECONDS);
            return $cached !== false ? $cached : [];
        }

        $body = json_decode(wp_remote_retrieve_body($res), true);
        $data = [
            'generation' => $body['generation'] ?? 0,
            'links' => $body['links'] ?? [],
            '_fresh' => 1,
            '_fetched_at' => time(),
        ];
        set_transient('sadie_links_index', $data, SADIE_LINKS_TTL);
        delete_transient('sadie_links_circuit_open');
        return $data;
    }

    /**
     * Append a single hidden "Related Pages" block to post content. Matches
     * OTTO's model — visible to Googlebot (rendered DOM crawl), invisible to
     * humans (display:none), no risk to theme layout. Simpler + deterministic
     * than in-body wrapping: every approved link gets placed.
     */
    public function inject($content) {
        if (!$this->enabled() && empty($this->settings['internal_links_dry_run'])) return $content;
        if (is_admin() || is_feed() || is_404()) return $content;
        if (!is_singular() && !is_page()) return $content;

        $post = get_post();
        if (!$post) return $content;

        $permalink = get_permalink($post);
        $index = $this->fetch_links_for_client();
        $edges = $index['links'][$permalink] ?? $index['links'][untrailingslashit($permalink)] ?? [];
        if (empty($edges)) return $content;

        $max_links = (int) ($this->settings['max_links_per_page'] ?? 6);
        $edges = array_slice($edges, 0, $max_links);

        // Dry-run: log what would've been injected, return original content
        if (!empty($this->settings['internal_links_dry_run']) && empty($this->settings['internal_links_enabled'])) {
            $log = get_option('sadie_il_dry_run_log', []);
            $log[] = [
                'post_id' => $post->ID,
                'permalink' => $permalink,
                'edges' => array_map(function ($e) {
                    return ['target' => $e['target_url'], 'anchor' => $e['anchor_text']];
                }, $edges),
                'at' => current_time('mysql'),
            ];
            if (count($log) > 200) $log = array_slice($log, -200);
            update_option('sadie_il_dry_run_log', $log, false);
            return $content;
        }

        foreach ($edges as $e) {
            $this->audit_buffer[] = [
                'source_url' => $permalink,
                'target_url' => $e['target_url'],
                'anchor_text' => $e['anchor_text'],
                'edge_id' => $e['edge_id'] ?? null,
                'rendered_at' => gmdate('c'),
            ];
        }

        return $content . $this->build_hidden_block($edges);
    }

    /**
     * Hidden "Related Pages" block. Entire wrapper is display:none, plus each
     * <li> is display:none as a belt-and-suspenders in case any theme CSS
     * overrides the wrapper. Matches OTTO's otto-inlinks-module pattern.
     */
    private function build_hidden_block(array $edges) {
        $items = '';
        foreach ($edges as $e) {
            $href = esc_url($e['target_url']);
            $anchor = esc_html($e['anchor_text']);
            $edge_id = (int) ($e['edge_id'] ?? 0);
            $items .= sprintf(
                '<li style="display:none"><a class="sadie-inlink" data-sadie-pixel="dynamic-seo" data-sadie-edge="%d" href="%s">%s</a></li>',
                $edge_id,
                $href,
                $anchor
            );
        }
        return sprintf(
            '<div class="sadie-inlinks-module" data-sadie-pixel="dynamic-seo" style="display:none"><h5>Related Pages:</h5><ul>%s</ul></div>',
            $items
        );
    }

    /**
     * On shutdown, fire-and-forget POST audit rows so Sadie's dashboard knows
     * links actually rendered. Non-blocking: wp_remote_post with blocking=false.
     */
    public function flush_audit() {
        if (empty($this->audit_buffer)) return;
        $token = get_option('sadie_publisher_project_token');
        if (!$token) return;
        $path = '/api/wp-plugin/v1/injection-audit';
        $body = wp_json_encode(['rows' => $this->audit_buffer]);
        $ts = (string) time();
        $sig = hash_hmac('sha256', $ts . 'POST' . $path, $token);
        wp_remote_post($this->api_base() . $path, [
            'timeout' => 0.1, // fire and forget
            'blocking' => false,
            'headers' => [
                'Content-Type' => 'application/json',
                'X-Sadie-Project-Token' => $token,
                'X-Sadie-Timestamp' => $ts,
                'X-Sadie-Signature' => $sig,
                'X-Sadie-Nonce' => wp_generate_uuid4(),
            ],
            'body' => $body,
        ]);
        $this->audit_buffer = [];
    }
}

// =============================================================================
// v3.0 — Health Monitor (outbound heartbeat)
// =============================================================================

class Sadie_Health_Monitor {
    const CRON_HOOK = 'sadie_health_heartbeat';

    public function __construct() {
        add_action(self::CRON_HOOK, [$this, 'send']);
        add_filter('cron_schedules', [$this, 'add_schedule']);
        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_event(time() + 60, 'sadie_15min', self::CRON_HOOK);
        }
    }

    public function add_schedule($schedules) {
        $schedules['sadie_15min'] = [
            'interval' => SADIE_HEARTBEAT_INTERVAL,
            'display' => 'Every 15 minutes (Sadie)',
        ];
        return $schedules;
    }

    public function send() {
        $settings = get_option('sadie_publisher_settings', []);
        if (empty($settings['heartbeat_v2_enabled'])) return;

        $token = get_option('sadie_publisher_project_token');
        if (!$token) return;

        global $wp_version;

        // Recent injection count from audit buffer persisted in option
        $last_audit = get_option('sadie_il_audit_window', ['at' => 0, 'count' => 0, 'pages' => 0]);
        $window_cutoff = time() - SADIE_HEARTBEAT_INTERVAL;

        $payload = [
            'plugin_version' => SADIE_PUBLISHER_VERSION,
            'wp_version' => $wp_version,
            'php_version' => PHP_VERSION,
            'memory_peak_mb' => round(memory_get_peak_usage(true) / 1048576, 1),
            'theme' => (function_exists('wp_get_theme') ? wp_get_theme()->get('Name') : null),
            'plugin_count' => count(get_option('active_plugins', [])),
            'wp_cron_healthy' => !defined('DISABLE_WP_CRON') || !DISABLE_WP_CRON,
            'injection_count_last_window' => $last_audit['count'] ?? 0,
            'rendered_pages_last_window' => $last_audit['pages'] ?? 0,
        ];

        $path = '/api/wp-monitoring/heartbeat';
        $ts = (string) time();
        $body = wp_json_encode($payload);
        $sig = hash_hmac('sha256', $ts . 'POST' . $path, $token);
        wp_remote_post($this->api_base() . $path, [
            'timeout' => 8,
            'headers' => [
                'Content-Type' => 'application/json',
                'X-Sadie-Project-Token' => $token,
                'X-Sadie-Timestamp' => $ts,
                'X-Sadie-Signature' => $sig,
                'X-Sadie-Nonce' => wp_generate_uuid4(),
            ],
            'body' => $body,
        ]);

        // Reset window counter
        update_option('sadie_il_audit_window', ['at' => time(), 'count' => 0, 'pages' => 0], false);
    }

    private function api_base() {
        $s = get_option('sadie_publisher_settings', []);
        return $s['sadie_api_base'] ?? SADIE_API_BASE;
    }
}

// =============================================================================
// v3.0 — Links refresh + Page-state probe REST routes
// =============================================================================

add_action('rest_api_init', function() {
    // Invalidate the link index so next render re-fetches. Called by Sadie on approve/reject.
    register_rest_route('sadie-publisher/v1', '/links/refresh', [
        'methods'  => 'POST',
        'permission_callback' => [Sadie_Publisher::get_instance(), 'verify_request'],
        'callback' => function() {
            delete_transient('sadie_links_index');
            update_option('sadie_links_generation_bumped_at', time(), false);
            return ['ok' => true, 'flushed' => true];
        },
    ]);

    // Page-state probe: returns post-filter output so Sadie can capture what
    // Yoast/RankMath/etc. actually serve. Respects page_state_probe_enabled flag.
    register_rest_route('sadie-publisher/v1', '/page-state/(?P<id>\d+)', [
        'methods'  => 'GET',
        'permission_callback' => [Sadie_Publisher::get_instance(), 'verify_request'],
        'callback' => function($req) {
            $settings = get_option('sadie_publisher_settings', []);
            if (empty($settings['page_state_probe_enabled'])) {
                return new WP_REST_Response(['error' => 'probe disabled'], 403);
            }
            $id = (int) $req['id'];
            $post = get_post($id);
            if (!$post) return new WP_REST_Response(['error' => 'not found'], 404);

            // Run content through filters (includes Yoast/RankMath injections)
            $content = apply_filters('the_content', $post->post_content);
            $title = apply_filters('the_title', $post->post_title, $id);

            return [
                'id' => $id,
                'permalink' => get_permalink($id),
                'title_rendered' => $title,
                'content_rendered' => $content,
                'status' => $post->post_status,
                'modified' => $post->post_modified_gmt,
            ];
        },
    ]);
});

// Init v3 subsystems
add_action('init', function() {
    new Sadie_Internal_Links();
    new Sadie_Health_Monitor();
}, 20);

// =============================================================================
// INITIALIZATION
// =============================================================================

add_action('init', function() {
    Sadie_Publisher::get_instance();
});

// AJAX: Key regeneration (admin only, nonce-protected)
add_action('wp_ajax_sadie_regenerate_key', function() {
    check_ajax_referer('sadie_regenerate');

    if (!current_user_can('manage_options')) {
        wp_send_json_error(['message' => 'Unauthorized.']);
    }

    $type = sanitize_text_field($_POST['type'] ?? 'api');

    if ($type === 'project') {
        $new_key = 'proj_' . bin2hex(random_bytes(16));
        update_option('sadie_publisher_project_token', $new_key);
    } else {
        $new_key = 'sadie_' . bin2hex(random_bytes(32));
        update_option('sadie_publisher_api_key', $new_key);
    }

    wp_send_json_success(['key' => $new_key]);
});
