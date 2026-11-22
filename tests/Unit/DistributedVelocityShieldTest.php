<?php
declare(strict_types=1);

namespace WebCareProScanner\Tests\Unit;

use PHPUnit\Framework\TestCase;
use WebCareProScanner\Firewall\DistributedVelocityShield;
use WebCareProScanner\System\AuditLogger;

/**
 * Concurrency, lock safety, and atomic fenced write regression tests for DistributedVelocityShield.
 */
class DistributedVelocityShieldTest extends TestCase {

    protected function setUp(): void {
        parent::setUp();
        wp_set_current_user(0);
    }

    /**
     * Test that atomic_fenced_ext_cache_set on Memcached or generic object cache returns false
     * and strictly NEVER calls wp_cache_set() when multi-key atomic Redis Lua is unavailable.
     */
    public function test_fenced_ext_cache_set_fails_closed_without_redis_lua(): void {
        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $method = $refl->getMethod('atomic_fenced_ext_cache_set');
        $method->setAccessible(true);

        $lock_key = 'dvs_test_mock_lock_' . bin2hex(random_bytes(4));
        $owner_token = 'token_valid_123';
        $target_key = 'dvs_test_mock_target_' . bin2hex(random_bytes(4));
        $target_val = 'test_value_payload';
        $group = 'webcareproscan_dvs';

        // 1. Simulate generic object cache without Redis client using a proper object-cache mock
        global $wp_object_cache;
        $prev_cache = $wp_object_cache;

        $mock_generic_cache = new class {
            public int $set_calls = 0;
            public int $get_calls = 0;
            public array $storage = [];

            public function get($key, $group = 'default', $force = false, &$found = null) {
                $this->get_calls++;
                $found = isset($this->storage[$group][$key]);
                return $this->storage[$group][$key] ?? false;
            }

            public function set($key, $data, $group = 'default', $expire = 0) {
                $this->set_calls++;
                $this->storage[$group][$key] = $data;
                return true;
            }

            public function add($key, $data, $group = 'default', $expire = 0) {
                if (isset($this->storage[$group][$key])) {
                    return false;
                }
                $this->storage[$group][$key] = $data;
                return true;
            }

            public function delete($key, $group = 'default') {
                unset($this->storage[$group][$key]);
                return true;
            }

            public function incr($key, $offset = 1, $group = 'default') {
                $current = (int) ($this->storage[$group][$key] ?? 0);
                $this->storage[$group][$key] = $current + $offset;
                return $this->storage[$group][$key];
            }
        };

        $wp_object_cache = $mock_generic_cache;

        try {
            $result = $method->invoke(null, $lock_key, $owner_token, $target_key, $target_val, $group, 60);
            $this->assertFalse($result, 'atomic_fenced_ext_cache_set must fail closed (return false) on generic object cache.');
            $this->assertSame(0, $mock_generic_cache->set_calls, 'Target key must not receive write calls on fail-closed backend.');
            $this->assertFalse(wp_cache_get($target_key, $group), 'Target key must not exist in cache.');
        } finally {
            $wp_object_cache = $prev_cache;
        }

        // 2. Simulate Memcached wrapper object ($wp_object_cache->m)
        $mock_memcached_cache = new class {
            public $m;
            public function __construct() {
                $this->m = new class {
                    public int $set_calls = 0;
                    public function getByKey($server_key, $key, $cb = null, &$cas = null) { return 'token_valid_123'; }
                    public function get($key, $cb = null, &$cas = null) { return 'token_valid_123'; }
                    public function set($key, $val, $exp = 0) { $this->set_calls++; return true; }
                };
            }
            public function get($key, $group = 'default', $force = false, &$found = null) { return false; }
            public function set($key, $data, $group = 'default', $expire = 0) { return true; }
        };
        $wp_object_cache = $mock_memcached_cache;

        try {
            $result = $method->invoke(null, $lock_key, $owner_token, $target_key, $target_val, $group, 60);
            $this->assertFalse($result, 'atomic_fenced_ext_cache_set must fail closed on Memcached since multi-key CAS is unsupported.');
            $this->assertSame(0, $mock_memcached_cache->m->set_calls, 'Memcached client must not receive non-atomic set calls.');
        } finally {
            $wp_object_cache = $prev_cache;
        }
    }

    /**
     * Test that atomic_fenced_apcu_store returns false immediately without calling apcu_store()
     * or executing destructive post-write apcu_delete() rollbacks.
     */
    public function test_fenced_apcu_store_fails_closed_without_destructive_rollbacks(): void {
        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $method = $refl->getMethod('atomic_fenced_apcu_store');
        $method->setAccessible(true);

        $lock_key = 'dvs_mock_apcu_lock_' . bin2hex(random_bytes(4));
        $owner_token = 88888888;
        $target_key = 'dvs_mock_apcu_target_' . bin2hex(random_bytes(4));
        $target_val = 'apcu_sample_payload';

        // Pre-seed target key to verify it is NEVER deleted or destroyed
        if (function_exists('apcu_store') && ini_get('apc.enabled') && (php_sapi_name() !== 'cli' || ini_get('apc.enable_cli'))) {
            apcu_store($target_key, 'existing_worker_data', 60);
        }

        $result = $method->invoke(null, $lock_key, $owner_token, $target_key, $target_val, 60);
        $this->assertFalse($result, 'atomic_fenced_apcu_store must fail closed immediately because APCu lacks multi-key CAS.');

        if (function_exists('apcu_fetch') && ini_get('apc.enabled') && (php_sapi_name() !== 'cli' || ini_get('apc.enable_cli'))) {
            $this->assertSame('existing_worker_data', apcu_fetch($target_key), 'Pre-existing target key must NEVER be destroyed by post-write rollbacks.');
            apcu_delete($target_key);
        }
    }

    /**
     * Test that release_ext_cache_lock returns false and lets the lease expire naturally
     * when the backend is Memcached or a generic object cache without Redis Lua.
     */
    public function test_release_ext_cache_lock_fails_safe_on_memcached_and_generic_cache(): void {
        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $method = $refl->getMethod('release_ext_cache_lock');
        $method->setAccessible(true);

        $lock_key = 'dvs_test_rel_lock_' . bin2hex(random_bytes(4));
        $owner_token = 'token_owner_abc';
        $group = 'webcareproscan_dvs';

        global $wp_object_cache;
        $prev_cache = $wp_object_cache;

        // Mock generic cache without redis
        $wp_object_cache = new \stdClass();

        try {
            // Calling release on generic object cache must return false without deleting the key
            $released = $method->invoke(null, $lock_key, $owner_token, $group);
            $this->assertFalse($released, 'release_ext_cache_lock must return false on generic cache to allow safe TTL expiry.');
        } finally {
            $wp_object_cache = $prev_cache;
        }

        // Mock Memcached wrapper without redis
        $mock_mc = new \stdClass();
        $mock_mc->m = new class {
            public int $del_calls = 0;
            public function delete($key) { $this->del_calls++; return true; }
            public function deleteByKey($s, $key) { $this->del_calls++; return true; }
        };
        $wp_object_cache = $mock_mc;

        try {
            $released = $method->invoke(null, $lock_key, $owner_token, $group);
            $this->assertFalse($released, 'release_ext_cache_lock must return false on Memcached and never bypass key prefixing.');
            $this->assertSame(0, $mock_mc->m->del_calls, 'Raw Memcached client delete methods must never be called.');
        } finally {
            $wp_object_cache = $prev_cache;
        }
    }

    /**
     * Test that non-Redis backends (APCu, Memcached, generic object cache) accurately count unique_ips
     * via the single-lock atomic flock(LOCK_EX) file backend without silently returning 0.
     * Uses an isolated temp directory for DVS storage and an explicit non-Redis object cache mock.
     */
    public function test_non_redis_backend_routes_to_atomic_file_and_counts_unique_ips_accurately(): void {
        global $wp_object_cache;
        $prev_cache = $wp_object_cache;
        $prev_custom_storage = DistributedVelocityShield::$custom_storage_dir;

        $temp_storage_dir = sys_get_temp_dir() . '/webcare_test_dvs_non_redis_' . bin2hex(random_bytes(4));
        wp_mkdir_p($temp_storage_dir);
        DistributedVelocityShield::$custom_storage_dir = $temp_storage_dir;

        // Explicitly install a deterministic non-Redis object cache mock
        $wp_object_cache = new class {
            public array $items = [];
            public function get($key, $group = 'default', $force = false, &$found = null) {
                $found = isset($this->items["{$group}:{$key}"]);
                return $this->items["{$group}:{$key}"] ?? false;
            }
            public function set($key, $val, $group = 'default', $exp = 0) {
                $this->items["{$group}:{$key}"] = $val;
                return true;
            }
            public function add($key, $val, $group = 'default', $exp = 0) {
                if (isset($this->items["{$group}:{$key}"])) return false;
                $this->items["{$group}:{$key}"] = $val;
                return true;
            }
            public function incr($key, $offset = 1, $group = 'default') {
                $current = $this->items["{$group}:{$key}"] ?? 0;
                $this->items["{$group}:{$key}"] = $current + $offset;
                return $this->items["{$group}:{$key}"];
            }
            public function delete($key, $group = 'default') {
                unset($this->items["{$group}:{$key}"]);
                return true;
            }
        };

        $cache_key = 'dvs_test_non_redis_' . bin2hex(random_bytes(4));
        $ip1 = '198.51.100.11';
        $ip2 = '198.51.100.12';

        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $appendMethod = $refl->getMethod('append_sliding_event');
        $appendMethod->setAccessible(true);
        $getMetricsMethod = $refl->getMethod('get_sliding_metrics');
        $getMetricsMethod->setAccessible(true);

        try {
            // Append events for IP 1 and IP 2
            $res1 = $appendMethod->invoke(null, $cache_key, $ip1, 'Auth failure 1', []);
            $this->assertSame(1, $res1['count']);
            $this->assertSame(1, $res1['unique_ips']);

            $res2 = $appendMethod->invoke(null, $cache_key, $ip1, 'Auth failure 2 from same IP', []);
            $this->assertSame(2, $res2['count']);
            $this->assertSame(1, $res2['unique_ips']);

            $res3 = $appendMethod->invoke(null, $cache_key, $ip2, 'Auth failure 3 from distinct IP', []);
            $this->assertSame(3, $res3['count']);
            $this->assertSame(2, $res3['unique_ips'], 'DVS must accurately count exactly 2 unique IPs via file backend.');

            $final_metrics = $getMetricsMethod->invoke(null, $cache_key);
            $this->assertSame(3, $final_metrics['count']);
            $this->assertSame(2, $final_metrics['unique_ips'], 'get_sliding_metrics must accurately return exactly 2 unique IPs.');
        } finally {
            $wp_object_cache = $prev_cache;
            DistributedVelocityShield::$custom_storage_dir = $prev_custom_storage;

            // Clean up temporary files in test directory
            if (is_dir($temp_storage_dir)) {
                $files = glob($temp_storage_dir . '/*');
                if (is_array($files)) {
                    foreach ($files as $f) {
                        @unlink($f);
                    }
                }
                @rmdir($temp_storage_dir);
            }
        }
    }

    /**
     * Test single atomic Redis Lua EVAL execution with INCR and SADD.
     */
    public function test_redis_lua_eval_single_atomic_slice_tracking(): void {
        global $wp_object_cache;
        $prev_cache = $wp_object_cache;

        // Mock Redis client with in-memory Sets and Counters simulating EVAL script
        $mock_redis = new class {
            public int $eval_calls = 0;
            public array $counters = [];
            public array $sets = [];

            public function eval($script, $args = [], $num_keys = 0) {
                $this->eval_calls++;
                $count_key = $args[0];
                $set_key = $args[1];
                $ev_key = $args[2];
                $ip_hash = $args[3];
                $ttl = (int) $args[4];
                $event_id = $args[5] ?? 'default_ev';

                if (!isset($this->sets[$ev_key])) {
                    $this->sets[$ev_key] = [];
                }

                // Deduplicate replay of same event_id
                if (isset($this->sets[$ev_key][$event_id])) {
                    return [
                        $this->counters[$count_key] ?? 0,
                        count($this->sets[$set_key] ?? []),
                    ];
                }
                $this->sets[$ev_key][$event_id] = true;

                if (!isset($this->counters[$count_key])) {
                    $this->counters[$count_key] = 0;
                }
                $this->counters[$count_key]++;

                if (!isset($this->sets[$set_key])) {
                    $this->sets[$set_key] = [];
                }
                $this->sets[$set_key][$ip_hash] = true;

                return [
                    $this->counters[$count_key],
                    count($this->sets[$set_key]),
                ];
            }

            public function sMembers($key) {
                return array_keys($this->sets[$key] ?? []);
            }

            public function get($key) {
                return $this->counters[$key] ?? null;
            }
        };

        $mock_object_cache = new class($mock_redis) {
            public $redis;
            public array $data = [];
            public function __construct($r) { $this->redis = $r; }
            public function build_key($key, $group) { return "{$group}:{$key}"; }
            public function get($key, $group = 'default', $force = false, &$found = null) {
                $k = $this->build_key($key, $group);
                $found = isset($this->redis->counters[$k]);
                return $this->redis->counters[$k] ?? false;
            }
            public function set($key, $val, $group = 'default', $exp = 0) {
                $this->data[$this->build_key($key, $group)] = $val;
                return true;
            }
            public function add($key, $val, $group = 'default', $exp = 0) { return true; }
            public function incr($key, $offset = 1, $group = 'default') { return 1; }
            public function delete($key, $group = 'default') { return true; }
        };

        $wp_object_cache = $mock_object_cache;

        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $hasRedis = $refl->getMethod('has_atomic_redis_lua_backend');
        $hasRedis->setAccessible(true);
        $appendMethod = $refl->getMethod('append_sliding_event');
        $appendMethod->setAccessible(true);
        $getMetricsMethod = $refl->getMethod('get_sliding_metrics');
        $getMetricsMethod->setAccessible(true);

        $cache_key = 'dvs_test_redis_lua_' . bin2hex(random_bytes(4));
        $ip1 = '203.0.113.51';
        $ip2 = '203.0.113.52';

        $prev_ext = function_exists('wp_using_ext_object_cache') ? wp_using_ext_object_cache() : false;
        if (function_exists('wp_using_ext_object_cache')) {
            wp_using_ext_object_cache(true);
        }

        try {
            // Redis Lua backend must be recognized as active
            $this->assertTrue($hasRedis->invoke(null), 'has_atomic_redis_lua_backend must return true when Redis client with eval() is present.');

            // Worker records first event
            $m1 = $appendMethod->invoke(null, $cache_key, $ip1, 'Auth fail 1', []);
            $this->assertSame(1, $mock_redis->eval_calls);
            $this->assertSame(1, $m1['count']);
            $this->assertSame(1, $m1['unique_ips']);

            // Worker records second event from same IP
            $m2 = $appendMethod->invoke(null, $cache_key, $ip1, 'Auth fail 2', []);
            $this->assertSame(2, $mock_redis->eval_calls);
            $this->assertSame(2, $m2['count']);
            $this->assertSame(1, $m2['unique_ips']);

            // Worker records third event from different IP
            $m3 = $appendMethod->invoke(null, $cache_key, $ip2, 'Auth fail 3', []);
            $this->assertSame(3, $mock_redis->eval_calls);
            $this->assertSame(3, $m3['count']);
            $this->assertSame(2, $m3['unique_ips']);

            $final = $getMetricsMethod->invoke(null, $cache_key);
            $this->assertSame(3, $final['count']);
            $this->assertSame(2, $final['unique_ips']);
        } finally {
            $wp_object_cache = $prev_cache;
            if (function_exists('wp_using_ext_object_cache')) {
                wp_using_ext_object_cache($prev_ext);
            }
        }
    }

    /**
     * Test file-lock exhaustion behavior: holding LOCK_EX in a fixture beyond retry budget
     * drops velocity event without corrupting file and logs dvs_file_lock_exhausted.
     * Uses an isolated temporary directory for AuditLogger to protect production logs.
     */
    public function test_file_lock_exhaustion_drops_event_and_logs_audit_diagnostic(): void {
        $cache_key = 'dvs_test_flock_exhaust_' . bin2hex(random_bytes(4));
        $now = time();
        $bucket_id = (int) floor($now / 10);
        $ip_hash = 'testhash999';

        $upload_dir = wp_upload_dir();
        $base_dir = (empty($upload_dir['error']) && !empty($upload_dir['basedir'])) ? $upload_dir['basedir'] : '';
        $this->assertNotEmpty($base_dir, 'Upload directory must be available.');

        $dir = rtrim($base_dir, '/\\') . '/webcare-pro-security/rate-limits';
        if (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        $file = $dir . '/dvs_' . substr(md5($cache_key), 0, 8) . '.php';
        $lock_file = $file . '.lock';

        // 1. Pre-seed file with initial known valid payload
        $initial_payload = "<?php exit; ?>\n" . json_encode([
            $bucket_id => ['count' => 1, 'ips' => [$ip_hash]]
        ]);
        file_put_contents($file, $initial_payload);

        // 2. Hold LOCK_EX exclusively on the .lock sidecar file to force lock exhaustion on competing workers
        $competing_fp = fopen($lock_file, 'c+');
        $this->assertIsResource($competing_fp);
        $locked = flock($competing_fp, LOCK_EX | LOCK_NB);
        $this->assertTrue($locked, 'Test runner must acquire exclusive lock on test fixture lock file.');

        // 3. Isolate AuditLogger using temporary directory override
        $isolated_audit_dir = sys_get_temp_dir() . '/webcare_test_audit_' . bin2hex(random_bytes(4));
        wp_mkdir_p($isolated_audit_dir);

        $prev_custom_dir = AuditLogger::$custom_log_dir;
        AuditLogger::$custom_log_dir = $isolated_audit_dir;

        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $fileInc = $refl->getMethod('file_atomic_dvs_increment');
        $fileInc->setAccessible(true);

        try {
            // Worker attempts to increment under lock exhaustion
            $startTime = microtime(true);
            $fileInc->invoke(null, $cache_key, $bucket_id, 'different_ip');
            $elapsed = microtime(true) - $startTime;

            // Worker must have waited for its 20 retries (~200ms)
            $this->assertGreaterThanOrEqual(0.18, $elapsed, 'Worker must respect bounded wait retries (200ms).');

            // 4. Verify file payload remained completely unmodified (event dropped safely)
            $content = file_get_contents($file);
            $this->assertSame($initial_payload, $content, 'File contents must remain unmodified when lock acquisition times out.');

            // 5. Verify exact AuditLogger diagnostic message in isolated test audit log file
            $audit_log_file = $isolated_audit_dir . '/audit.log.php';
            $this->assertFileExists($audit_log_file, 'Isolated AuditLogger log file must exist after exhaustion event.');
            $audit_content = file_get_contents($audit_log_file);
            $this->assertStringContainsString('dvs_file_lock_exhausted', $audit_content, 'Audit log must record dvs_file_lock_exhausted event type.');
            $this->assertStringContainsString('DVS file write-lock acquisition timed out after 20 retries (200ms). Velocity event dropped.', $audit_content, 'Audit log must contain exact diagnostic message.');
        } finally {
            flock($competing_fp, LOCK_UN);
            fclose($competing_fp);

            // Restore AuditLogger custom dir and cleanup temp directory
            AuditLogger::$custom_log_dir = $prev_custom_dir;
            if (file_exists($isolated_audit_dir . '/audit.log.php')) {
                @unlink($isolated_audit_dir . '/audit.log.php');
            }
            if (file_exists($isolated_audit_dir . '/.htaccess')) {
                @unlink($isolated_audit_dir . '/.htaccess');
            }
            if (file_exists($isolated_audit_dir . '/index.php')) {
                @unlink($isolated_audit_dir . '/index.php');
            }
            @rmdir($isolated_audit_dir);

            if (file_exists($file)) {
                @unlink($file);
            }
            if (file_exists($lock_file)) {
                @unlink($lock_file);
            }
        }
    }

    /**
     * Test idempotent Redis Lua execution: replaying the same event_id does not double-increment,
     * and an ambiguous Redis EVAL failure does NOT split-write to the local file backend.
     */
    public function test_redis_lua_idempotency_and_no_file_split_write_on_eval_failure(): void {
        global $wp_object_cache;
        $prev_cache = $wp_object_cache;
        $prev_custom_storage = DistributedVelocityShield::$custom_storage_dir;

        $temp_storage_dir = sys_get_temp_dir() . '/webcare_test_dvs_no_split_' . bin2hex(random_bytes(4));
        wp_mkdir_p($temp_storage_dir);
        DistributedVelocityShield::$custom_storage_dir = $temp_storage_dir;

        $mock_redis = new class {
            public int $eval_calls = 0;
            public array $counters = [];
            public array $sets = [];
            public bool $fail_eval = false;

            public function eval($script, $args = [], $num_keys = 0) {
                $this->eval_calls++;
                if ($this->fail_eval) {
                    throw new \RuntimeException('Redis connection timeout during EVAL');
                }

                $count_key = $args[0];
                $set_key   = $args[1];
                $ev_key    = $args[2];
                $ip_hash   = $args[3];
                $ttl       = (int) $args[4];
                $event_id  = $args[5] ?? 'default_ev';

                if (!isset($this->sets[$ev_key])) {
                    $this->sets[$ev_key] = [];
                }

                // Deduplicate replay of same event_id
                if (isset($this->sets[$ev_key][$event_id])) {
                    return [
                        $this->counters[$count_key] ?? 0,
                        count($this->sets[$set_key] ?? []),
                    ];
                }
                $this->sets[$ev_key][$event_id] = true;

                if (!isset($this->counters[$count_key])) {
                    $this->counters[$count_key] = 0;
                }
                $this->counters[$count_key]++;

                if (!isset($this->sets[$set_key])) {
                    $this->sets[$set_key] = [];
                }
                $this->sets[$set_key][$ip_hash] = true;

                return [
                    $this->counters[$count_key],
                    count($this->sets[$set_key]),
                ];
            }

            public function sMembers($key) {
                return array_keys($this->sets[$key] ?? []);
            }

            public function get($key) {
                return $this->counters[$key] ?? null;
            }
        };

        $mock_object_cache = new class($mock_redis) {
            public $redis;
            public function __construct($r) { $this->redis = $r; }
            public function build_key($key, $group) { return "{$group}:{$key}"; }
            public function get($key, $group = 'default', $force = false, &$found = null) {
                $k = $this->build_key($key, $group);
                $found = isset($this->redis->counters[$k]);
                return $this->redis->counters[$k] ?? false;
            }
            public function set($key, $val, $group = 'default', $exp = 0) { return true; }
            public function add($key, $val, $group = 'default', $exp = 0) { return true; }
            public function incr($key, $offset = 1, $group = 'default') { return 1; }
            public function delete($key, $group = 'default') { return true; }
        };

        $wp_object_cache = $mock_object_cache;

        $prev_ext = function_exists('wp_using_ext_object_cache') ? wp_using_ext_object_cache() : false;
        if (function_exists('wp_using_ext_object_cache')) {
            wp_using_ext_object_cache(true);
        }

        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $appendMethod = $refl->getMethod('append_sliding_event');
        $appendMethod->setAccessible(true);

        $cache_key = 'dvs_test_idempotent_' . bin2hex(random_bytes(4));
        $ip = '192.0.2.77';

        try {
            // 1. First record succeeds via Redis
            $res1 = $appendMethod->invoke(null, $cache_key, $ip, 'Failure 1', []);
            $this->assertSame(1, $res1['count']);
            $this->assertSame(1, $res1['unique_ips']);
            $this->assertTrue($res1['complete']);
            $this->assertFalse($res1['degraded']);

            // 2. Simulate EVAL failure after retry
            $mock_redis->fail_eval = true;
            $res2 = $appendMethod->invoke(null, $cache_key, $ip, 'Failure 2 with Redis down', []);

            // Ambiguous failure must return degraded response without split-writing to file backend
            $this->assertSame(0, $res2['count']);
            $this->assertSame(0, $res2['unique_ips']);
            $this->assertFalse($res2['complete']);
            $this->assertTrue($res2['degraded']);

            // Verify no files were created in local storage directory
            $files = glob($temp_storage_dir . '/*');
            $this->assertEmpty($files, 'Ambiguous Redis EVAL failure must never split-write into local file store.');
        } finally {
            $wp_object_cache = $prev_cache;
            DistributedVelocityShield::$custom_storage_dir = $prev_custom_storage;
            if (function_exists('wp_using_ext_object_cache')) {
                wp_using_ext_object_cache($prev_ext);
            }

            if (is_dir($temp_storage_dir)) {
                $files = glob($temp_storage_dir . '/*');
                if (is_array($files)) {
                    foreach ($files as $f) {
                        @unlink($f);
                    }
                }
                @rmdir($temp_storage_dir);
            }
        }
    }

    /**
     * Test that a partial/failed slice read in get_sliding_metrics() returns complete=false and degraded=true.
     */
    public function test_partial_slice_read_returns_degraded_status(): void {
        global $wp_object_cache;
        $prev_cache = $wp_object_cache;

        $mock_redis = new class {
            public int $get_calls = 0;
            public function get($key) {
                $this->get_calls++;
                // Simulate failure on every 3rd slice call
                if ($this->get_calls % 3 === 0) {
                    throw new \RuntimeException('Redis slice read timeout');
                }
                return '2';
            }
            public function sMembers($key) {
                return ['testhash1'];
            }
            public function eval($script, $args = [], $num_keys = 0) {
                return [1, 1];
            }
        };

        $mock_object_cache = new class($mock_redis) {
            public $redis;
            public function __construct($r) { $this->redis = $r; }
            public function build_key($key, $group) { return "{$group}:{$key}"; }
            public function get($key, $group = 'default', $force = false, &$found = null) {
                throw new \RuntimeException('Object cache fallback failure');
            }
            public function set($key, $val, $group = 'default', $exp = 0) { return true; }
            public function add($key, $val, $group = 'default', $exp = 0) { return true; }
            public function incr($key, $offset = 1, $group = 'default') { return 1; }
            public function delete($key, $group = 'default') { return true; }
        };

        $wp_object_cache = $mock_object_cache;

        $prev_ext = function_exists('wp_using_ext_object_cache') ? wp_using_ext_object_cache() : false;
        if (function_exists('wp_using_ext_object_cache')) {
            wp_using_ext_object_cache(true);
        }

        $refl = new \ReflectionClass(DistributedVelocityShield::class);
        $getMetricsMethod = $refl->getMethod('get_sliding_metrics');
        $getMetricsMethod->setAccessible(true);

        $cache_key = 'dvs_test_partial_slice_' . bin2hex(random_bytes(4));

        try {
            $hasRedisMethod = $refl->getMethod('has_atomic_redis_lua_backend');
            $hasRedisMethod->setAccessible(true);
            $this->assertTrue($hasRedisMethod->invoke(null), 'has_atomic_redis_lua_backend must be true for test_partial_slice_read_returns_degraded_status');

            $metrics = $getMetricsMethod->invoke(null, $cache_key);
            $this->assertFalse($metrics['complete'], 'Partial read with failed slices must mark complete as false.');
            $this->assertTrue($metrics['degraded'], 'Partial read with failed slices must mark degraded as true.');
            $this->assertGreaterThan(0, $metrics['count'], 'Partial metrics must still sum accessible slice counts.');
        } finally {
            $wp_object_cache = $prev_cache;
            if (function_exists('wp_using_ext_object_cache')) {
                wp_using_ext_object_cache($prev_ext);
            }
        }
    }
}
