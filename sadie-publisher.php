<?php
/**
 * Plugin Name: Sadie Publisher
 * Plugin URI: https://brotherlyseo.com
 * Description: One-way content publishing from Sadie Blog Command Center to WordPress. Security-hardened, builder-aware.
 * Version: 2.0.2
 * Author: Sadie SEO
 * License: GPL v2 or later
 * Text Domain: sadie-publisher
 * Requires PHP: 7.4
 * Requires at least: 5.8
 *
 * Changelog:
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

define('SADIE_PUBLISHER_VERSION', '2.0.2');
define('SADIE_PUBLISHER_MIN_PHP', '7.4');
define('SADIE_PUBLISHER_RATE_LIMIT', 30); // requests per minute
define('SADIE_PUBLISHER_NONCE_TTL', 300); // 5 minute nonce window

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
                'Sadie Publisher requires PHP %s or higher. You are running PHP %s.',
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
            'Sadie Publisher',
            'Sadie Publisher',
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
            <h1>Sadie Publisher <small style="font-size:0.5em;color:#666;">v<?php echo esc_html(SADIE_PUBLISHER_VERSION); ?></small></h1>
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
                            <span class="sadie-api-key" id="sadie-api-key"><?php echo esc_html($api_key); ?></span>
                            <button type="button" class="button button-small sadie-copy-btn" onclick="sadieCopy('<?php echo esc_js($api_key); ?>')">Copy</button>
                            <button type="button" class="button button-small" onclick="sadieRegenKey('api')">Regenerate</button>
                        </td>
                    </tr>
                    <tr>
                        <th>Project Token</th>
                        <td>
                            <span class="sadie-api-key" id="sadie-project-token"><?php echo esc_html($project_token); ?></span>
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

    public function handle_options_set($request) {
        $ip = $this->get_client_ip();
        $params = $request->get_json_params();
        $options = $params['options'] ?? null;
        if (empty($options) || !is_array($options)) {
            return new WP_Error('bad_request', 'options object required.', ['status' => 400]);
        }
        $updated = [];
        $failed  = [];
        foreach ($options as $key => $value) {
            $key = sanitize_key($key);
            if (!$key) continue;
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
        $this->audit_log('options_set', empty($failed), $ip, implode(',', $updated));
        return new WP_REST_Response([
            'updated' => $updated,
            'failed'  => $failed,
        ], 200);
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
            'message' => 'Sadie Publisher is connected.',
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
            'posts' => [
                'published' => $post_counts->publish ?? 0,
                'draft' => $post_counts->draft ?? 0,
                'pending' => $post_counts->pending ?? 0,
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

        $result = wp_update_post($post_data, true);
        if (is_wp_error($result)) {
            $this->audit_log('update', false, $ip, $result->get_error_message());
            return $result;
        }

        // Update SEO if provided
        if (!empty($params['seo'])) {
            $this->set_seo_meta($post_id, $params['seo']);
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
            return new WP_Error('forbidden', 'Can only delete posts created by Sadie Publisher.', ['status' => 403]);
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
