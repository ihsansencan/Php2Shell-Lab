<?php
$phpVersion = PHP_VERSION;
$vulnerable = version_compare($phpVersion, '8.4.27', '<');
$uploadProgress = ini_get('session.upload_progress.enabled') ? 'On' : 'Off';
$displayErrors = ini_get('display_errors') ?: 'Off';
$memoryLimit = ini_get('memory_limit');
$server = $_SERVER['SERVER_SOFTWARE'] ?? 'unknown';
$serverShort = str_replace('Apache/', '', $server);
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Php2Shell Lab — CVE-2026-109618 / CVE-2026-109619</title>
<link rel="stylesheet" href="assets/style.css">
</head>
<body>

<header>
  <div class="wrap">
    <span class="badge">AUTHORIZED LAB USE ONLY</span>
    <h1>Php2Shell <span>Lab</span></h1>
    <p class="subtitle">
      An isolated Docker environment demonstrating pre-auth remote code execution
      in PHP 8.4.x via two chained use-after-free vulnerabilities.
    </p>
    <div class="meta-row">
      <span class="chip">PHP <b><?= htmlspecialchars($phpVersion) ?></b></span>
      <span class="chip <?= $vulnerable ? 'bad' : 'ok' ?>">
        <b><?= $vulnerable ? 'VULNERABLE' : 'PATCHED' ?></b>
      </span>
      <span class="chip">Apache <b><?= htmlspecialchars($serverShort) ?></b></span>
      <span class="chip">CVSS <b>9.2</b></span>
    </div>
  </div>
</header>

<main class="wrap">

  <section id="cve">
    <h2><span class="num">01</span>Vulnerabilities</h2>
    <p class="section-lead">Two use-after-free conditions in PHP's request lifecycle, chained into one-shot RCE.</p>
    <div class="cve-grid">

      <article class="cve-card">
        <span class="cvss">CVSS 9.2</span>
        <div class="id">CVE-2026-109618</div>
        <h3>Session ID dangling during OOM cleanup</h3>
        <p>
          When a <code>multipart/form-data</code> request hits memory exhaustion inside the
          rfc1867 cleanup path, the session ID, <code>send_cookie</code> and module data pointers
          remain dangling in the worker after the bailout.
        </p>
        <ul>
          <li><b>Type</b> Use-After-Free</li>
          <li><b>Trigger</b> session.upload_progress + OOM</li>
          <li><b>Auth</b> None</li>
          <li><b>Fixed</b> PHP 8.4.27</li>
        </ul>
      </article>

      <article class="cve-card">
        <span class="cvss">CVSS 9.2</span>
        <div class="id">CVE-2026-109619</div>
        <h3>Dangling hash_serialize_verifier</h3>
        <p>
          A second low-cost OOM leaves <code>PS(hash_serialize_verifier)</code> dangling.
          A fake reference plus a forged <code>zend_array</code> with
          <code>pDestructor = zif_system</code> turns request shutdown into <code>system()</code>.
        </p>
        <ul>
          <li><b>Type</b> Use-After-Free</li>
          <li><b>Trigger</b> low-cost OOM + fake zval</li>
          <li><b>Auth</b> None</li>
          <li><b>Fixed</b> PHP 8.4.27</li>
        </ul>
      </article>

    </div>
  </section>

  <section id="chain">
    <h2><span class="num">02</span>Exploit Chain</h2>
    <p class="section-lead">Pure HTTP. No target-side files, no debugger, no application code.</p>
    <div class="chain">

      <div class="step">
        <span class="tag">A1</span>
        <div>
          <h4>send_cookie OOM</h4>
          <p>A crafted multipart body exhausts memory inside the rfc1867 END cleanup,
          leaving <code>PS(id)</code>, <code>PS(send_cookie)</code> and
          <code>PS(mod_data)</code> dangling in the worker.</p>
        </div>
        <span class="arrow">▼</span>
      </div>

      <div class="step">
        <span class="tag">B1</span>
        <div>
          <h4>Stale-ID out-of-bounds read</h4>
          <p>A forged <code>zend_string</code> header re-activates the stale ID chunk.
          The resulting <code>Set-Cookie</code> leaks ~800 KB of heap, yielding
          the <code>libphp</code> base and the main chunk address.</p>
        </div>
        <span class="arrow">▼</span>
      </div>

      <div class="step">
        <span class="tag">A2</span>
        <div>
          <h4>cheap-OOM</h4>
          <p>A second memory-pressure request frees
          <code>PS(hash_serialize_verifier)</code> without clearing the pointer.</p>
        </div>
        <span class="arrow">▼</span>
      </div>

      <div class="step">
        <span class="tag">B2</span>
        <div>
          <h4>Fake reference + forged zend_array</h4>
          <p>A spray of fake references overwrites the dangling verifier. The final
          request carries a forged <code>zend_array</code> whose
          <code>pDestructor</code> points to <code>zif_system</code> and whose
          argument is the attacker command.</p>
        </div>
        <span class="arrow">▼</span>
      </div>

      <div class="step rce">
        <span class="tag">RCE</span>
        <div>
          <h4>system(cmd) at request shutdown</h4>
          <p><code>zend_hash_destroy</code> fires during shutdown and invokes
          <code>system()</code> as <code>www-data</code>.</p>
        </div>
      </div>

    </div>
  </section>

  <section id="status">
    <h2><span class="num">03</span>Lab Status</h2>
    <p class="section-lead">Live configuration of this container, read on each request.</p>
    <div class="status">
      <div class="status-head">
        <span class="dot r"></span><span class="dot y"></span><span class="dot g"></span>
        <span style="margin-left:6px">php2shell — container state</span>
      </div>
      <div class="status-body">
        <div class="status-row"><span class="k">php.version</span><span class="v <?= $vulnerable ? 'bad' : 'ok' ?>"><?= htmlspecialchars($phpVersion) ?></span></div>
        <div class="status-row"><span class="k">php.status</span><span class="v <?= $vulnerable ? 'bad' : 'ok' ?>"><?= $vulnerable ? 'vulnerable' : 'patched' ?></span></div>
        <div class="status-row"><span class="k">session.upload_progress</span><span class="v <?= $uploadProgress === 'On' ? 'warn' : 'ok' ?>"><?= htmlspecialchars($uploadProgress) ?></span></div>
        <div class="status-row"><span class="k">display_errors</span><span class="v"><?= htmlspecialchars($displayErrors) ?></span></div>
        <div class="status-row"><span class="k">memory_limit</span><span class="v"><?= htmlspecialchars($memoryLimit) ?></span></div>
        <div class="status-row"><span class="k">apache.worker</span><span class="v">single prefork child</span></div>
      </div>
    </div>
  </section>

  <section id="poc">
    <h2><span class="num">04</span>Proof of Concept</h2>
    <p class="section-lead">Run from the host. The output file is read back from the container.</p>

    <div class="cmd-block">
      <div class="head"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span> verify</div>
<pre><span class="prompt">$</span> python poc/php2shell_poc.py --port 80 --container Php2Shell --cmd "id>/out/p1"

<span class="comment">[try 1] A1: END-cleanup send_cookie OOM</span>
<span class="comment">[try 1] B1: stale-id OOB read (chunk base + libphp)</span>
<span class="comment">      decoded=819208  zval_ptr_dtor=0x...  libphp=0x...</span>
<span class="comment">[try 1] A2 + B2: main=0x...  S=0x...  zif_system=0x...</span>
<span class="out">[4/4] RCE OK:
uid=33(www-data) gid=33(www-data) groups=33(www-data)</span></pre>
    </div>

    <div class="cmd-block">
      <div class="head"><span class="dot r"></span><span class="dot y"></span><span class="dot g"></span> custom command</div>
<pre><span class="prompt">$</span> python poc/php2shell_poc.py --port 80 --container Php2Shell --cmd "pwd>/out/p1"

<span class="out">[4/4] RCE OK:
/var/www/html</span></pre>
    </div>
  </section>

  <section id="mitigation">
    <h2><span class="num">05</span>Mitigation</h2>
    <p class="section-lead">Apply in order. The lab can be re-tested after each step.</p>
    <div class="mit">
      <div class="mit-item">
        <span class="n">01</span>
        <div>
          <h4>Upgrade PHP</h4>
          <p>Move to <code>8.4.27</code> or later. This is the only complete fix.</p>
        </div>
      </div>
      <div class="mit-item">
        <span class="n">02</span>
        <div>
          <h4>Disable upload progress</h4>
          <p>Set <code>session.upload_progress.enabled=Off</code> as a temporary workaround
          until the upgrade is deployed.</p>
        </div>
      </div>
      <div class="mit-item">
        <span class="n">03</span>
        <div>
          <h4>Limit request bodies</h4>
          <p>Cap <code>multipart/form-data</code> size at the reverse proxy. Large bodies
          are a prerequisite for the OOM-based trigger.</p>
        </div>
      </div>
      <div class="mit-item">
        <span class="n">04</span>
        <div>
          <h4>Isolate mod_php</h4>
          <p>Prefer PHP-FPM over Apache <code>mod_php</code>. The exploit targets the
          prefork worker's request lifecycle directly.</p>
        </div>
      </div>
    </div>
  </section>

</main>

<footer>
  <div class="wrap">
    <span>Php2Shell Lab — Author: <a href="https://github.com/ihsansencan" target="_blank" rel="noopener"><code>IhsanSencan</code></a></span>
    <span><a href="https://github.com/ihsansencan/Php2Shell-Lab" target="_blank" rel="noopener">github.com/ihsansencan/Php2Shell-Lab</a> · Educational use only · MIT</span>
  </div>
</footer>

</body>
</html>