<?php
declare(strict_types=1);

/**
 * DBest Innovation - repair & maintenance request handler.
 * Receives the form from repair-maintenance.html, validates it, re-encodes the photos
 * (which strips hidden metadata such as GPS), stores a copy outside the public web
 * folder and emails the request to the team.
 */

const OWNER_EMAIL      = 'info@dbestinnovation.com';
const FROM_EMAIL       = 'no-reply@dbestinnovation.com';
const SITE_NAME        = 'DBest Innovation';
const SITE_PHONE_WA    = '918527747545';
const MAX_PHOTOS       = 10;
const MAX_PHOTO_BYTES  = 8 * 1024 * 1024;   // per uploaded photo
const MAX_PIXELS       = 40000000;          // guards against decompression bombs
const OUT_MAX_SIDE     = 1800;              // stored/emailed photos are scaled to this
const RATE_LIMIT       = 5;                 // requests per IP per hour
const MIN_FILL_SECONDS = 5;                 // humans take longer than this to fill the form
const RETAIN_DAYS      = 365;               // stored requests older than this are deleted

const SERVICES = [
    'electrical'    => 'Electrical',
    'plumbing'      => 'Plumbing & sanitary',
    'roofing'       => 'Roofing & waterproofing',
    'painting'      => 'Painting & polishing',
    'cleaning'      => 'Cleaning',
    'deep_cleaning' => 'Deep cleaning',
    'false_ceiling' => 'False ceiling & gypsum',
    'carpentry'     => 'Carpentry & furniture',
    'flooring'      => 'Flooring',
    'glass'         => 'Glass, partitions & doors',
    'hvac'          => 'AC / HVAC',
    'civil'         => 'Civil & masonry',
    'fire_safety'   => 'Fire safety',
    'cctv_data'     => 'CCTV, data & low-voltage',
    'amc'           => 'Annual maintenance contract (AMC)',
    'other'         => 'Other',
];
const PROPERTY_TYPES = [
    'office'    => 'Office',
    'cafe'      => 'Café / restaurant',
    'retail'    => 'Retail store / showroom',
    'industrial'=> 'Warehouse / industrial',
    'healthcare'=> 'Clinic / healthcare',
    'education' => 'School / institute',
    'villa'     => 'Villa / residence',
    'other'     => 'Other',
];
const URGENCY = [
    'emergency' => 'Emergency (same day)',
    'soon'      => 'Within 2-3 days',
    'week'      => 'This week',
    'flexible'  => 'Planned / flexible',
];
const SLOTS = [
    'morning'   => 'Morning (9 am - 12 pm)',
    'afternoon' => 'Afternoon (12 pm - 4 pm)',
    'evening'   => 'Evening (4 pm - 7 pm)',
    'any'       => 'Any time',
];

header('Content-Type: application/json; charset=utf-8');
header('X-Robots-Tag: noindex, nofollow');
header('Cache-Control: no-store');

function respond(int $code, array $data): void
{
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function fail(int $code, string $message): void
{
    respond($code, ['ok' => false, 'message' => $message]);
}

function clean($v, int $max): string
{
    if (!is_string($v)) {
        return '';
    }
    $v = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $v) ?? '';
    return mb_substr(trim($v), 0, $max);
}

function clean_line($v, int $max): string
{
    return trim(preg_replace('/\s+/', ' ', clean($v, $max)) ?? '');
}

function storage_dir(): ?string
{
    $override = getenv('DBEST_DATA_DIR');
    $candidates = $override ? [$override] : [dirname(__DIR__, 2) . '/maintenance-data', __DIR__ . '/_data'];
    foreach ($candidates as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        if (is_dir($dir) && is_writable($dir)) {
            if (strpos(realpath($dir) ?: $dir, realpath(dirname(__DIR__)) ?: dirname(__DIR__)) === 0) {
                // Inside the public folder: block all web access.
                @file_put_contents($dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
            }
            return $dir;
        }
    }
    return null;
}

function client_hash(string $dir): string
{
    $saltFile = $dir . '/.salt';
    if (!is_file($saltFile)) {
        @file_put_contents($saltFile, bin2hex(random_bytes(16)));
    }
    $salt = (string) @file_get_contents($saltFile);
    return hash('sha256', $salt . ($_SERVER['REMOTE_ADDR'] ?? 'unknown'));
}

function rate_limited(string $dir): bool
{
    $rateDir = $dir . '/rate';
    if (!is_dir($rateDir)) {
        @mkdir($rateDir, 0750, true);
    }
    $file = $rateDir . '/' . client_hash($dir) . '.json';
    $now = time();
    $hits = [];
    if (is_file($file)) {
        $hits = json_decode((string) file_get_contents($file), true) ?: [];
        $hits = array_values(array_filter($hits, static fn($t) => is_int($t) && $t > $now - 3600));
    }
    if (count($hits) >= RATE_LIMIT) {
        return true;
    }
    $hits[] = $now;
    @file_put_contents($file, json_encode($hits), LOCK_EX);
    return false;
}

function purge_old(string $dir): void
{
    $reqDir = $dir . '/requests';
    if (!is_dir($reqDir)) {
        return;
    }
    $cutoff = time() - RETAIN_DAYS * 86400;
    foreach (glob($reqDir . '/*', GLOB_ONLYDIR) ?: [] as $d) {
        if (filemtime($d) < $cutoff) {
            foreach (glob($d . '/*') ?: [] as $f) {
                @unlink($f);
            }
            @rmdir($d);
        }
    }
}

function normalise_files(array $files): array
{
    $out = [];
    if (!isset($files['name'])) {
        return $out;
    }
    if (!is_array($files['name'])) {
        return [$files];
    }
    foreach ($files['name'] as $i => $name) {
        $out[] = [
            'name'     => $name,
            'tmp_name' => $files['tmp_name'][$i] ?? '',
            'error'    => $files['error'][$i] ?? UPLOAD_ERR_NO_FILE,
            'size'     => $files['size'][$i] ?? 0,
        ];
    }
    return $out;
}

/** Re-encode an uploaded image as a clean, size-limited JPEG. Returns JPEG bytes or null. */
function reencode_image(string $tmp): ?string
{
    $info = @getimagesize($tmp);
    if (!$info || !in_array($info[2], [IMAGETYPE_JPEG, IMAGETYPE_PNG, IMAGETYPE_WEBP, IMAGETYPE_GIF], true)) {
        return null;
    }
    if ($info[0] < 1 || $info[1] < 1 || $info[0] * $info[1] > MAX_PIXELS) {
        return null;
    }
    $src = @imagecreatefromstring((string) file_get_contents($tmp));
    if (!$src) {
        return null;
    }
    $w = imagesx($src);
    $h = imagesy($src);
    $scale = min(1.0, OUT_MAX_SIDE / max($w, $h));
    $nw = max(1, (int) round($w * $scale));
    $nh = max(1, (int) round($h * $scale));
    $dst = imagecreatetruecolor($nw, $nh);
    imagefill($dst, 0, 0, imagecolorallocate($dst, 255, 255, 255));
    imagecopyresampled($dst, $src, 0, 0, 0, 0, $nw, $nh, $w, $h);
    ob_start();
    imagejpeg($dst, null, 82);
    $bytes = (string) ob_get_clean();
    imagedestroy($src);
    imagedestroy($dst);
    return $bytes !== '' ? $bytes : null;
}

function send_mail(string $to, string $subject, string $headers, string $body): bool
{
    $sink = getenv('DBEST_MAIL_SINK');
    if ($sink) {
        if (!is_dir($sink)) {
            @mkdir($sink, 0777, true);
        }
        $name = $sink . '/' . date('His') . '-' . substr(md5($to . $subject), 0, 6) . '.eml';
        return file_put_contents($name, "To: $to\r\nSubject: $subject\r\n$headers\r\n\r\n$body") !== false;
    }
    return @mail($to, $subject, $body, $headers, '-f' . FROM_EMAIL);
}

function mime_subject(string $s): string
{
    return mb_encode_mimeheader($s, 'UTF-8', 'B', "\r\n");
}

function build_mail(string $text, array $attachments, array $extraHeaders): array
{
    $headers = array_merge([
        'From: ' . SITE_NAME . ' Website <' . FROM_EMAIL . '>',
        'MIME-Version: 1.0',
        'X-Mailer: DBest-Website',
    ], $extraHeaders);

    if (!$attachments) {
        $headers[] = 'Content-Type: text/plain; charset=UTF-8';
        $headers[] = 'Content-Transfer-Encoding: base64';
        return [implode("\r\n", $headers), chunk_split(base64_encode($text))];
    }

    $boundary = 'dbest_' . bin2hex(random_bytes(8));
    $headers[] = 'Content-Type: multipart/mixed; boundary="' . $boundary . '"';
    $body  = "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n";
    $body .= chunk_split(base64_encode($text));
    foreach ($attachments as $name => $bytes) {
        $body .= "--$boundary\r\nContent-Type: image/jpeg; name=\"$name\"\r\n";
        $body .= "Content-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"$name\"\r\n\r\n";
        $body .= chunk_split(base64_encode($bytes));
    }
    $body .= "--$boundary--";
    return [implode("\r\n", $headers), $body];
}

/* ------------------------------------------------------------------ */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fail(405, 'Please submit the form from the website.');
}

if (empty($_POST) && empty($_FILES) && (int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 0) {
    fail(413, 'Your photos are too large to send in one go. Please remove a few photos or try again.');
}

// Honeypot: real visitors never fill this. Pretend success so bots learn nothing.
if (clean($_POST['website'] ?? '', 50) !== '') {
    respond(200, ['ok' => true, 'ref' => 'DB-000000-0000']);
}
if ((float) ($_POST['elapsed'] ?? 0) < MIN_FILL_SECONDS) {
    fail(429, 'That was very quick. Please check your details and try again.');
}

$dir = storage_dir();
if ($dir === null) {
    error_log('DBest: no writable storage directory');
    fail(500, 'We could not save your request right now. Please WhatsApp or call us instead.');
}
if (rate_limited($dir)) {
    fail(429, 'Too many requests from your connection. Please wait a while or call us directly.');
}

// ---- validate fields ----
$errors = [];
$name    = clean_line($_POST['name'] ?? '', 80);
$company = clean_line($_POST['company'] ?? '', 100);
$phone   = preg_replace('/\D+/', '', clean($_POST['phone'] ?? '', 20)) ?? '';
if (strlen($phone) === 12 && strpos($phone, '91') === 0) {
    $phone = substr($phone, 2);
} elseif (strlen($phone) === 11 && $phone[0] === '0') {
    $phone = substr($phone, 1);
}
$email   = clean_line($_POST['email'] ?? '', 120);
$address = clean($_POST['address'] ?? '', 250);
$city    = clean_line($_POST['city'] ?? '', 60);
$pin     = preg_replace('/\D+/', '', clean($_POST['pin'] ?? '', 10)) ?? '';
$details = clean($_POST['details'] ?? '', 1500);
$property = clean_line($_POST['property'] ?? '', 20);
$urgency  = clean_line($_POST['urgency'] ?? '', 20);
$slot     = clean_line($_POST['slot'] ?? '', 20);
$visitDate = clean_line($_POST['visit_date'] ?? '', 10);

if (mb_strlen($name) < 2) { $errors[] = 'Please enter your name.'; }
if (!preg_match('/^[6-9]\d{9}$/', $phone)) { $errors[] = 'Please enter a valid 10-digit mobile number.'; }
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) { $errors[] = 'That email address does not look right.'; }
if (mb_strlen($address) < 5) { $errors[] = 'Please enter the site address.'; }
if (mb_strlen($city) < 2) { $errors[] = 'Please enter the city.'; }
if ($pin !== '' && !preg_match('/^\d{6}$/', $pin)) { $errors[] = 'PIN code should be 6 digits.'; }
if (!isset(PROPERTY_TYPES[$property])) { $errors[] = 'Please choose the property type.'; }
if (!isset(URGENCY[$urgency])) { $errors[] = 'Please choose how urgent this is.'; }
if (!isset(SLOTS[$slot])) { $slot = 'any'; }
if (($_POST['consent'] ?? '') !== 'yes') { $errors[] = 'Please tick the consent box so we can use your details and photos.'; }

$services = [];
foreach ((array) ($_POST['services'] ?? []) as $s) {
    if (is_string($s) && isset(SERVICES[$s])) {
        $services[$s] = SERVICES[$s];
    }
}
if (!$services) { $errors[] = 'Please select at least one service.'; }

if ($visitDate !== '') {
    $d = DateTime::createFromFormat('Y-m-d', $visitDate);
    $today = new DateTime('today');
    if (!$d || $d->format('Y-m-d') !== $visitDate || $d < $today || $d > (clone $today)->modify('+90 days')) {
        $errors[] = 'Please pick a visit date within the next 90 days.';
    }
}

$files = normalise_files($_FILES['photos'] ?? []);
$files = array_values(array_filter($files, static fn($f) => ($f['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_NO_FILE));
if (count($files) > MAX_PHOTOS) { $errors[] = 'You can upload up to ' . MAX_PHOTOS . ' photos.'; }

if ($errors) {
    fail(422, implode(' ', $errors));
}

// ---- process photos ----
$photos = [];
foreach ($files as $i => $f) {
    if (($f['error'] ?? 0) !== UPLOAD_ERR_OK || !is_uploaded_file((string) $f['tmp_name'])) {
        fail(422, 'One of your photos could not be uploaded. Please try again with fewer or smaller photos.');
    }
    if (($f['size'] ?? 0) > MAX_PHOTO_BYTES) {
        fail(422, 'One of your photos is larger than 8 MB. Please choose a smaller one.');
    }
    $bytes = reencode_image((string) $f['tmp_name']);
    if ($bytes === null) {
        fail(422, 'One of the files is not a valid photo (use JPG, PNG or WebP).');
    }
    $photos['photo-' . ($i + 1) . '.jpg'] = $bytes;
}

// ---- save a copy ----
$ref = 'DB-' . date('ymd') . '-' . strtoupper(bin2hex(random_bytes(2)));
$reqDir = $dir . '/requests/' . $ref;
@mkdir($reqDir, 0750, true);
$record = [
    'ref' => $ref, 'created' => date('c'),
    'name' => $name, 'company' => $company, 'phone' => $phone, 'email' => $email,
    'address' => $address, 'city' => $city, 'pin' => $pin,
    'property' => PROPERTY_TYPES[$property], 'urgency' => URGENCY[$urgency],
    'services' => array_values($services), 'visit_date' => $visitDate, 'visit_slot' => SLOTS[$slot],
    'details' => $details, 'photos' => array_keys($photos), 'client' => client_hash($dir),
];
@file_put_contents($reqDir . '/request.json', json_encode($record, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE), LOCK_EX);
foreach ($photos as $fname => $bytes) {
    @file_put_contents($reqDir . '/' . $fname, $bytes);
}
if (random_int(1, 20) === 1) {
    purge_old($dir);
}

// ---- email the team ----
$lines = [
    "New repair & maintenance request  -  $ref",
    str_repeat('-', 50),
    'Urgency:       ' . URGENCY[$urgency],
    'Services:      ' . implode(', ', $services),
    'Property:      ' . PROPERTY_TYPES[$property],
    '',
    'Name:          ' . $name . ($company !== '' ? " ($company)" : ''),
    'Phone:         ' . $phone . '   (WhatsApp: https://wa.me/91' . $phone . ')',
    'Email:         ' . ($email !== '' ? $email : '-'),
    '',
    'Site address:  ' . str_replace(["\r", "\n"], ' ', $address),
    'City / PIN:    ' . $city . ($pin !== '' ? " - $pin" : ''),
    'Preferred visit: ' . ($visitDate !== '' ? $visitDate : 'no date given') . ', ' . SLOTS[$slot],
    '',
    'Details:',
    $details !== '' ? $details : '(none)',
    '',
    'Photos attached: ' . count($photos),
    '',
    'Next step: call the customer to confirm the site visit, then send pricing after inspection.',
];
$text = implode("\r\n", $lines);

$attachBudget = 18 * 1024 * 1024;
$attach = [];
$used = 0;
foreach ($photos as $fname => $bytes) {
    if ($used + strlen($bytes) > $attachBudget) { break; }
    $attach[$fname] = $bytes;
    $used += strlen($bytes);
}

$subjectCity = preg_replace('/[\r\n]+/', ' ', $city) ?? '';
$subject = mime_subject('[' . SITE_NAME . '] New request ' . $ref . ' - ' . implode(', ', array_slice(array_values($services), 0, 3)) . ' - ' . $subjectCity);
$extra = $email !== '' ? ['Reply-To: ' . $email] : [];
[$h, $b] = build_mail($text, $attach, $extra);
$sent = send_mail(OWNER_EMAIL, $subject, $h, $b);

if (!$sent) {
    error_log("DBest: owner email failed for $ref (saved in $reqDir)");
    fail(502, 'We saved your request but could not notify our team automatically. Please WhatsApp or call us on +91 85277 47545 and quote ' . $ref . '.');
}

// ---- confirmation to customer (optional) ----
if ($email !== '') {
    $confirm = "Hello $name,\r\n\r\nThank you for contacting " . SITE_NAME . ". We have received your repair & maintenance request.\r\n\r\n"
        . "Reference: $ref\r\nServices: " . implode(', ', $services) . "\r\nSite: $city\r\n\r\n"
        . "Our team will call you on $phone to confirm a site visit. Pricing is shared after the inspection.\r\n\r\n"
        . "Need to add something? Reply to this email or WhatsApp us on +91 85277 47545 with your reference.\r\n\r\n"
        . SITE_NAME . ", New Delhi\r\nhttps://dbestinnovation.com\r\n";
    [$ch, $cb] = build_mail($confirm, [], ['Reply-To: ' . OWNER_EMAIL]);
    send_mail($email, mime_subject('We received your request ' . $ref . ' - ' . SITE_NAME), $ch, $cb);
}

respond(200, ['ok' => true, 'ref' => $ref]);
