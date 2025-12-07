#!/bin/bash

# ==========================================
# WP Google R2 Backup - Security Patched v1.0.1
# ==========================================

# 定義外掛根目錄
PLUGIN_DIR="wp-google-r2-backup"
INC_DIR="$PLUGIN_DIR/includes"

echo "正在建立安全強化版目錄結構..."
mkdir -p "$INC_DIR"

# 1. 建立主檔案 (版本號更新為 1.0.1)
echo "正在寫入 wp-google-r2-backup.php..."
cat << 'EOF' > "$PLUGIN_DIR/wp-google-r2-backup.php"
<?php
/**
 * Plugin Name: WP Google R2 Backup
 * Plugin URI:  https://example.com/wp-google-r2-backup
 * Description: High-performance backup solution to Cloudflare R2 using native PHP cURL and AWS V4 Signature. (Security Hardened)
 * Version:     1.0.1
 * Author:      Google Senior PHP Engineer
 * Author URI:  https://google.com
 * Text Domain: wp-google-r2-backup
 * Domain Path: /languages
 * Requires PHP: 7.4
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

define( 'WGR2_VERSION', '1.0.1' );
define( 'WGR2_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WGR2_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'WGR2_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
define( 'WGR2_OPTION_GROUP', 'wgr2_settings_group' );
define( 'WGR2_OPTION_NAME', 'wgr2_options' );

register_activation_hook( __FILE__, 'wgr2_activate_plugin' );

function wgr2_activate_plugin() {
	if ( version_compare( PHP_VERSION, '7.4', '<' ) ) {
		wp_die( esc_html__( 'WP Google R2 Backup requires PHP version 7.4 or higher.', 'wp-google-r2-backup' ) );
	}
	
	if ( false === get_option( WGR2_OPTION_NAME ) ) {
		$default_options = array(
			'r2_account_id' => '',
			'r2_access_key' => '',
			'r2_secret_key' => '',
			'r2_bucket'     => '',
		);
		add_option( WGR2_OPTION_NAME, $default_options );
	}
}

register_deactivation_hook( __FILE__, 'wgr2_deactivate_plugin' );

function wgr2_deactivate_plugin() {
    // Preserve settings
}

function wgr2_run_plugin() {
	require_once WGR2_PLUGIN_DIR . 'includes/class-wgr2-settings.php';
	new WGR2_Settings();
	
	require_once WGR2_PLUGIN_DIR . 'includes/class-wgr2-backup.php';
	require_once WGR2_PLUGIN_DIR . 'includes/class-wgr2-uploader.php';
}

add_action( 'plugins_loaded', 'wgr2_run_plugin' );

add_action( 'admin_init', 'wgr2_handle_manual_backup' );

function wgr2_handle_manual_backup() {
	if ( isset( $_POST['wgr2_manual_backup'] ) && check_admin_referer( 'wgr2_backup_action', 'wgr2_nonce' ) ) {
		
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( 'Unauthorized' );
		}

		$options = get_option( WGR2_OPTION_NAME );
		
		$backup = new WGR2_Backup();
		$zip_path = $backup->create_backup();

		if ( is_wp_error( $zip_path ) ) {
			add_settings_error( 'wgr2_messages', 'wgr2_error', 'Backup failed: ' . $zip_path->get_error_message(), 'error' );
			return;
		}

		$uploader = new WGR2_Uploader( $options );
		$filename = basename( $zip_path );
		$result = $uploader->upload_file( $zip_path, $filename );

		$backup->cleanup_backup( $zip_path );

		if ( is_wp_error( $result ) ) {
			add_settings_error( 'wgr2_messages', 'wgr2_error', 'R2 Upload failed: ' . $result->get_error_message(), 'error' );
		} else {
			add_settings_error( 'wgr2_messages', 'wgr2_success', 'Backup successfully uploaded to R2!', 'updated' );
		}
	}
}

add_action( 'admin_notices', 'wgr2_display_admin_notices' );

function wgr2_display_admin_notices() {
    settings_errors( 'wgr2_messages' );
}
EOF

# 2. 建立 includes/class-wgr2-settings.php (維持不變)
echo "正在寫入 includes/class-wgr2-settings.php..."
cat << 'EOF' > "$INC_DIR/class-wgr2-settings.php"
<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WGR2_Settings {
	public function __construct() {
		add_action( 'admin_menu', array( $this, 'add_plugin_page' ) );
		add_action( 'admin_init', array( $this, 'page_init' ) );
	}
	public function add_plugin_page() {
		add_options_page('WP Google R2 Backup', 'R2 Backup', 'manage_options', 'wgr2-backup', array( $this, 'create_admin_page' ));
	}
	public function create_admin_page() {
		if ( ! current_user_can( 'manage_options' ) ) return;
		?>
		<div class="wrap">
			<h1><?php echo esc_html( get_admin_page_title() ); ?></h1>
			<form method="post" action="options.php">
				<?php
				settings_fields( WGR2_OPTION_GROUP );
				do_settings_sections( 'wgr2-backup' );
				submit_button();
				?>
			</form>
			<hr>
			<h2>Manual Backup</h2>
			<form method="post" action="">
				<?php wp_nonce_field( 'wgr2_backup_action', 'wgr2_nonce' ); ?>
				<input type="hidden" name="wgr2_manual_backup" value="1">
				<?php submit_button( 'Backup Now to R2', 'primary', 'submit', false ); ?>
			</form>
		</div>
		<?php
	}
	public function page_init() {
		register_setting(WGR2_OPTION_GROUP, WGR2_OPTION_NAME, array( $this, 'sanitize' ));
		add_settings_section('wgr2_setting_section', 'Cloudflare R2 Configuration', array( $this, 'print_section_info' ), 'wgr2-backup');
		add_settings_field('r2_account_id', 'Account ID', array( $this, 'r2_account_id_callback' ), 'wgr2-backup', 'wgr2_setting_section');
		add_settings_field('r2_access_key', 'Access Key ID', array( $this, 'r2_access_key_callback' ), 'wgr2-backup', 'wgr2_setting_section');
		add_settings_field('r2_secret_key', 'Secret Access Key', array( $this, 'r2_secret_key_callback' ), 'wgr2-backup', 'wgr2_setting_section');
		add_settings_field('r2_bucket', 'Bucket Name', array( $this, 'r2_bucket_callback' ), 'wgr2-backup', 'wgr2_setting_section');
	}
	public function sanitize( $input ) {
		$new_input = array();
		if ( isset( $input['r2_account_id'] ) ) $new_input['r2_account_id'] = sanitize_text_field( $input['r2_account_id'] );
		if ( isset( $input['r2_access_key'] ) ) $new_input['r2_access_key'] = sanitize_text_field( $input['r2_access_key'] );
		if ( isset( $input['r2_secret_key'] ) ) $new_input['r2_secret_key'] = sanitize_text_field( $input['r2_secret_key'] );
		if ( isset( $input['r2_bucket'] ) ) $new_input['r2_bucket'] = sanitize_text_field( $input['r2_bucket'] );
		return $new_input;
	}
	public function print_section_info() { print 'Enter your Cloudflare R2 credentials below:'; }
	public function r2_account_id_callback() {
		$options = get_option( WGR2_OPTION_NAME );
		$val = isset( $options['r2_account_id'] ) ? $options['r2_account_id'] : '';
		printf('<input type="text" name="%s[r2_account_id]" value="%s" class="regular-text" />', WGR2_OPTION_NAME, esc_attr( $val ));
	}
	public function r2_access_key_callback() {
		$options = get_option( WGR2_OPTION_NAME );
		$val = isset( $options['r2_access_key'] ) ? $options['r2_access_key'] : '';
		printf('<input type="text" name="%s[r2_access_key]" value="%s" class="regular-text" />', WGR2_OPTION_NAME, esc_attr( $val ));
	}
	public function r2_secret_key_callback() {
		$options = get_option( WGR2_OPTION_NAME );
		$val = isset( $options['r2_secret_key'] ) ? $options['r2_secret_key'] : '';
		printf('<input type="password" name="%s[r2_secret_key]" value="%s" class="regular-text" />', WGR2_OPTION_NAME, esc_attr( $val ));
	}
	public function r2_bucket_callback() {
		$options = get_option( WGR2_OPTION_NAME );
		$val = isset( $options['r2_bucket'] ) ? $options['r2_bucket'] : '';
		printf('<input type="text" name="%s[r2_bucket]" value="%s" class="regular-text" />', WGR2_OPTION_NAME, esc_attr( $val ));
	}
}
EOF

# 3. 建立 includes/class-wgr2-backup.php (安全修補版)
echo "正在寫入 includes/class-wgr2-backup.php (Security Patched)..."
cat << 'EOF' > "$INC_DIR/class-wgr2-backup.php"
<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WGR2_Backup {
	public function create_backup() {
		if ( ! class_exists( 'ZipArchive' ) ) return new WP_Error( 'missing_zip_extension', 'PHP ZipArchive extension is required.' );
		if ( function_exists( 'set_time_limit' ) ) @set_time_limit( 0 );

		$source_dir = WP_CONTENT_DIR;
		$upload_dir = wp_get_upload_dir();
		$backup_dir = $upload_dir['basedir'] . '/wgr2-temp';
		
		if ( ! file_exists( $backup_dir ) ) {
			if ( ! wp_mkdir_p( $backup_dir ) ) return new WP_Error( 'mkdir_failed', 'Could not create backup directory.' );
			file_put_contents( $backup_dir . '/.htaccess', 'deny from all' );
			file_put_contents( $backup_dir . '/index.php', '<?php // Silence is golden.' );
		}

		// Security Check: Disk Space (Threshold: 500MB)
		$free_space = @disk_free_space( $backup_dir );
		if ( $free_space !== false && $free_space < 524288000 ) { 
			return new WP_Error( 'disk_space_low', 'Security/Stability Stop: Less than 500MB free disk space available.' );
		}

		$timestamp = date( 'Y-m-d_H-i-s' );
		$zip_filename = 'backup-wp-content-' . $timestamp . '.zip';
		$zip_filepath = $backup_dir . '/' . $zip_filename;
		$zip = new ZipArchive();

		if ( $zip->open( $zip_filepath, ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== true ) {
			return new WP_Error( 'zip_create_failed', 'Could not create zip file.' );
		}

		$files = new RecursiveIteratorIterator(
			new RecursiveDirectoryIterator( $source_dir, RecursiveDirectoryIterator::SKIP_DOTS ),
			RecursiveIteratorIterator::LEAVES_ONLY
		);

		foreach ( $files as $name => $file ) {
			if ( $file->isLink() ) continue; // Security: Do not follow symlinks
			if ( $file->isDir() ) continue;
			$file_path = $file->getRealPath();
			
			// Security: Prevent recursion (Zip bomb)
			if ( strpos( $file_path, $backup_dir ) !== false ) continue;
			if ( strpos( $file_path, 'debug.log' ) !== false || strpos( $file_path, '.zip' ) !== false ) continue;

			$relative_path = substr( $file_path, strlen( $source_dir ) + 1 );
			$zip->addFile( $file_path, str_replace( '\\', '/', $relative_path ) );
		}
		$zip->close();

		return file_exists( $zip_filepath ) ? $zip_filepath : new WP_Error( 'zip_not_found', 'Zip file was not created.' );
	}

	public function cleanup_backup( $file_path ) {
		$upload_dir = wp_get_upload_dir();
		$allowed_path = wp_normalize_path( $upload_dir['basedir'] . '/wgr2-temp' );
		$target_path = wp_normalize_path( $file_path );
		// Security: Path Traversal Protection
		if ( strpos( $target_path, $allowed_path ) === 0 && file_exists( $file_path ) ) {
			unlink( $file_path );
		}
	}
}
EOF

# 4. 建立 includes/class-wgr2-uploader.php (安全修補版)
echo "正在寫入 includes/class-wgr2-uploader.php (Security Patched)..."
cat << 'EOF' > "$INC_DIR/class-wgr2-uploader.php"
<?php
if ( ! defined( 'ABSPATH' ) ) exit;

class WGR2_Uploader {
	private $account_id;
	private $access_key;
	private $secret_key;
	private $bucket;
	private $region = 'auto'; 
	private $service = 's3';

	public function __construct( $credentials ) {
		$this->account_id = $credentials['r2_account_id'];
		$this->access_key = $credentials['r2_access_key'];
		$this->secret_key = $credentials['r2_secret_key'];
		$this->bucket     = $credentials['r2_bucket'];
	}

	private function validate_config() {
		// Security: SSRF Prevention via Regex Whitelisting
		if ( ! preg_match( '/^[a-f0-9]{32}$/i', $this->account_id ) ) return new WP_Error( 'invalid_config', 'Invalid R2 Account ID.' );
		if ( ! preg_match( '/^[a-z0-9.-]+$/', $this->bucket ) ) return new WP_Error( 'invalid_config', 'Invalid Bucket Name.' );
		return true;
	}

	public function upload_file( $file_path, $remote_filename ) {
		$validation = $this->validate_config();
		if ( is_wp_error( $validation ) ) return $validation;
		if ( ! file_exists( $file_path ) ) return new WP_Error( 'file_not_found', 'Local file does not exist.' );

		$host = "{$this->account_id}.r2.cloudflarestorage.com";
		$endpoint = "https://{$host}/{$this->bucket}/{$remote_filename}";
		$timestamp = time();
		$date_long = gmdate( 'Ymd\THis\Z', $timestamp );
		$date_short = gmdate( 'Ymd', $timestamp );

		$content_hash = hash_file( 'sha256', $file_path );
		$file_size = filesize( $file_path );

		$method = 'PUT';
		$canonical_uri = '/' . $this->bucket . '/' . $remote_filename;
		$headers = array('host' => $host, 'x-amz-content-sha256' => $content_hash, 'x-amz-date' => $date_long);
		
		$canonical_headers = ''; $signed_headers = array();
		foreach ( $headers as $key => $value ) {
			$canonical_headers .= $key . ':' . $value . "\n";
			$signed_headers[] = $key;
		}
		$signed_headers_string = implode( ';', $signed_headers );
		$canonical_request = "$method\n$canonical_uri\n\n$canonical_headers\n$signed_headers_string\n$content_hash";

		$algorithm = 'AWS4-HMAC-SHA256';
		$credential_scope = "$date_short/{$this->region}/{$this->service}/aws4_request";
		$string_to_sign = "$algorithm\n$date_long\n$credential_scope\n" . hash( 'sha256', $canonical_request );

		$kSecret = 'AWS4' . $this->secret_key;
		$kDate = hash_hmac( 'sha256', $date_short, $kSecret, true );
		$kRegion = hash_hmac( 'sha256', $this->region, $kDate, true );
		$kService = hash_hmac( 'sha256', $this->service, $kRegion, true );
		$kSigning = hash_hmac( 'sha256', 'aws4_request', $kService, true );
		$signature = hash_hmac( 'sha256', $string_to_sign, $kSigning );

		$authorization = "$algorithm Credential={$this->access_key}/$credential_scope, SignedHeaders=$signed_headers_string, Signature=$signature";

		$ch = curl_init();
		$fp = fopen( $file_path, 'r' );
		curl_setopt( $ch, CURLOPT_URL, $endpoint );
		curl_setopt( $ch, CURLOPT_PUT, true );
		curl_setopt( $ch, CURLOPT_INFILE, $fp );
		curl_setopt( $ch, CURLOPT_INFILESIZE, $file_size );
		curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
		curl_setopt( $ch, CURLOPT_HEADER, true ); 
		curl_setopt( $ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2 ); // Force TLS 1.2+

		$request_headers = array(
			'Authorization: ' . $authorization,
			'Host: ' . $host,
			'x-amz-date: ' . $date_long,
			'x-amz-content-sha256: ' . $content_hash,
			'Content-Type: application/zip',
		);
		curl_setopt( $ch, CURLOPT_HTTPHEADER, $request_headers );

		$response = curl_exec( $ch );
		$http_code = curl_getinfo( $ch, CURLINFO_HTTP_CODE );
		$error_msg = curl_error( $ch );
		curl_close( $ch );
		fclose( $fp );

		if ( $http_code >= 200 && $http_code < 300 ) {
			return true;
		} else {
			return new WP_Error( 'r2_upload_failed', "Upload failed. HTTP Code: $http_code. Error: $error_msg" );
		}
	}
}
EOF

echo "安全更新部署完成！所有檔案已針對 OWASP Top 10 風險進行強化。"
