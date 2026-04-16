<?php
/**
 * Sadie Publisher Debug Script
 * Upload to WordPress root via File Manager, then visit: https://rea.co/sadie-debug.php
 * DELETE THIS FILE after debugging.
 */

error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h2>Sadie Publisher Debug</h2>";
echo "<pre>";

// 1. PHP version
echo "PHP Version: " . PHP_VERSION . "\n";
echo "PHP Major: " . PHP_MAJOR_VERSION . "." . PHP_MINOR_VERSION . "\n\n";

// 2. Check if str_ends_with exists (PHP 8.0+)
echo "str_ends_with() exists: " . (function_exists('str_ends_with') ? 'YES' : 'NO') . "\n";
echo "str_starts_with() exists: " . (function_exists('str_starts_with') ? 'YES' : 'NO') . "\n";
echo "str_contains() exists: " . (function_exists('str_contains') ? 'YES' : 'NO') . "\n\n";

// 3. Check plugin file exists
$plugin_path = __DIR__ . '/wp-content/plugins/sadie-publisher/sadie-publisher.php';
echo "Plugin path: $plugin_path\n";
echo "File exists: " . (file_exists($plugin_path) ? 'YES' : 'NO') . "\n";

if (file_exists($plugin_path)) {
    echo "File size: " . filesize($plugin_path) . " bytes\n";
    echo "File perms: " . substr(sprintf('%o', fileperms($plugin_path)), -4) . "\n";
    echo "File owner: " . posix_getpwuid(fileowner($plugin_path))['name'] . "\n\n";

    // 4. Read first 500 bytes to check header
    $content = file_get_contents($plugin_path);
    $first500 = substr($content, 0, 500);
    echo "=== First 500 bytes ===\n";
    echo htmlspecialchars($first500);
    echo "\n=== End ===\n\n";

    // 5. Check for BOM
    $bom = (substr($content, 0, 3) === "\xEF\xBB\xBF");
    echo "Has BOM: " . ($bom ? 'YES (BAD!)' : 'NO (good)') . "\n";

    // 6. Check for PHP 8+ functions in file
    $php8_funcs = ['str_ends_with', 'str_starts_with', 'str_contains', 'match(', 'enum ', 'readonly '];
    echo "\nPHP 8+ function scan:\n";
    foreach ($php8_funcs as $func) {
        $count = substr_count($content, $func);
        echo "  $func: " . ($count > 0 ? "$count FOUND (PROBLEM!)" : "0 (clean)") . "\n";
    }

    // 7. Try php -l syntax check
    echo "\nPHP lint check:\n";
    $output = [];
    $ret = 0;
    exec("php -l " . escapeshellarg($plugin_path) . " 2>&1", $output, $ret);
    foreach ($output as $line) {
        echo "  $line\n";
    }

    // 8. Check WP's get_plugin_data would see
    echo "\nHeader regex extraction:\n";
    if (preg_match('/Plugin Name:\s*(.+)/i', $content, $m)) {
        echo "  Plugin Name: " . trim($m[1]) . "\n";
    } else {
        echo "  Plugin Name: NOT FOUND (this is why WP says invalid header!)\n";
    }
    if (preg_match('/Version:\s*(.+)/i', $content, $m)) {
        echo "  Version: " . trim($m[1]) . "\n";
    }
    if (preg_match('/Description:\s*(.+)/i', $content, $m)) {
        echo "  Description: " . trim(substr($m[1], 0, 80)) . "...\n";
    }

    // 9. Check the plugin directory for extra files
    $dir = dirname($plugin_path);
    echo "\nFiles in plugin directory ($dir):\n";
    if (is_dir($dir)) {
        $files = scandir($dir);
        foreach ($files as $f) {
            if ($f === '.' || $f === '..') continue;
            echo "  $f (" . filesize("$dir/$f") . " bytes)\n";
        }
    } else {
        echo "  Directory does not exist!\n";
    }

    // 10. Check for other sadie-publisher installs
    echo "\nOther plugin directories with 'sadie':\n";
    $plugins_dir = __DIR__ . '/wp-content/plugins/';
    $dirs = scandir($plugins_dir);
    foreach ($dirs as $d) {
        if (stripos($d, 'sadie') !== false) {
            echo "  $d/\n";
        }
    }

    // 11. OPcache status
    echo "\nOPcache:\n";
    if (function_exists('opcache_get_status')) {
        $status = opcache_get_status(false);
        echo "  Enabled: " . ($status['opcache_enabled'] ? 'YES' : 'NO') . "\n";
        echo "  Cached scripts: " . ($status['opcache_statistics']['num_cached_scripts'] ?? 'unknown') . "\n";
        if (function_exists('opcache_is_script_cached')) {
            echo "  Plugin cached: " . (opcache_is_script_cached($plugin_path) ? 'YES (stale cache possible!)' : 'NO') . "\n";
        }
    } else {
        echo "  OPcache not available\n";
    }

} else {
    echo "\nPlugin file not found. Checking plugins directory:\n";
    $plugins_dir = __DIR__ . '/wp-content/plugins/';
    $dirs = scandir($plugins_dir);
    foreach ($dirs as $d) {
        if (stripos($d, 'sadie') !== false || stripos($d, 'publisher') !== false) {
            echo "  $d/\n";
            if (is_dir($plugins_dir . $d)) {
                $files = scandir($plugins_dir . $d);
                foreach ($files as $f) {
                    if ($f === '.' || $f === '..') continue;
                    echo "    $f\n";
                }
            }
        }
    }
}

echo "</pre>";
echo "<p><strong>DELETE THIS FILE after debugging!</strong></p>";
