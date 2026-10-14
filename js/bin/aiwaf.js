#!/usr/bin/env node

const path = require('path');
const { spawn } = require('child_process');
const pathManifest = require('../lib/pathManifest');
const fs = require('fs');

function print(obj) {
  process.stdout.write(`${JSON.stringify(obj, null, 2)}\n`);
}

async function clearBlocklist() {
  const blocklistManager = require('../lib/blocklistManager');
  const deleted = await blocklistManager.clear();
  print({ ok: true, cleared: deleted });
}

async function clearRequestLogs() {
  const requestLogStore = require('../lib/requestLogStore');
  const deleted = await requestLogStore.clear();
  print({ ok: true, cleared: deleted });
}

function runTrain() {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'train.js')], {
    stdio: 'inherit',
    env: process.env
  });
  child.on('exit', code => process.exit(code || 0));
}

function readJsonFile(filePath) {
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

function writeJsonFile(filePath, payload) {
  const resolved = path.resolve(filePath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  const temporary = `${resolved}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  fs.renameSync(temporary, resolved);
  return resolved;
}

function parseDuration(value) {
  if (value === undefined || value === null || value === '') return null;
  const match = String(value).trim().toLowerCase().match(/^(\d+)(s|m|h|d)?$/);
  if (!match) throw new Error('Duration must be like 900s, 15m, 24h, or 1d');
  const units = { s: 1, m: 60, h: 3600, d: 86400 };
  return Number(match[1]) * units[match[2] || 's'];
}

async function collectOperationalState() {
  const blocklistManager = require('../lib/blocklistManager');
  const exemptionStore = require('../lib/exemptionStore');
  const geoStore = require('../lib/geoStore');
  const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
  const modelStore = require('../lib/modelStore');
  const [blocklist, ipExemptions, pathExemptions, geo, dynamicKeywords, model] = await Promise.all([
    blocklistManager.exportRecords(),
    exemptionStore.listIps(),
    exemptionStore.listPaths(),
    geoStore.listBlockedCountries(),
    dynamicKeywordStore.list(100000),
    modelStore.load(process.env)
  ]);
  return {
    schema_version: '1.0',
    exported_at: new Date().toISOString(),
    blocklist,
    ip_exemptions: ipExemptions,
    path_exemptions: pathExemptions,
    geo_blocked_countries: geo,
    dynamic_keywords: dynamicKeywords,
    model
  };
}

async function exportOperationalState(filePath = 'aiwaf-export.json') {
  const state = await collectOperationalState();
  return print({ ok: true, output: writeJsonFile(filePath, state), counts: {
    blocklist: state.blocklist.length,
    ip_exemptions: state.ip_exemptions.length,
    path_exemptions: state.path_exemptions.length,
    geo: state.geo_blocked_countries.length,
    dynamic_keywords: state.dynamic_keywords.length
  } });
}

async function importOperationalState(filePath) {
  if (!filePath) throw new Error('Import file is required');
  const state = readJsonFile(filePath);
  const blocklistManager = require('../lib/blocklistManager');
  const exemptionStore = require('../lib/exemptionStore');
  const geoStore = require('../lib/geoStore');
  const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
  const modelStore = require('../lib/modelStore');
  const imported = { blocklist: await blocklistManager.importRecords(state.blocklist ?? state.blacklist ?? []) };
  for (const row of state.ip_exemptions || []) await exemptionStore.addIp(row.ip_address || row.ip, row.reason);
  for (const row of state.path_exemptions || []) await exemptionStore.addPath(row.path_prefix || row.path, row.reason);
  for (const row of state.geo_blocked_countries || []) await geoStore.addBlockedCountry(row.country_code || row.country, row.reason);
  for (const row of state.dynamic_keywords || []) await dynamicKeywordStore.add(row.keyword, row.count);
  if (state.model) await modelStore.save(process.env, state.model, state.model.metadata || {});
  imported.ip_exemptions = (state.ip_exemptions || []).length;
  imported.path_exemptions = (state.path_exemptions || []).length;
  imported.geo = (state.geo_blocked_countries || []).length;
  imported.dynamic_keywords = (state.dynamic_keywords || []).length;
  return print({ ok: true, imported });
}

async function operationalStatus() {
  const blocklistManager = require('../lib/blocklistManager');
  const exemptionStore = require('../lib/exemptionStore');
  const geoStore = require('../lib/geoStore');
  const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
  const requestLogStore = require('../lib/requestLogStore');
  const modelStore = require('../lib/modelStore');
  const [blocklist, ips, paths, geo, keywords, logs, model] = await Promise.all([
    blocklistManager.getStatistics(), exemptionStore.listIps(), exemptionStore.listPaths(),
    geoStore.listBlockedCountries(), dynamicKeywordStore.list(100000), requestLogStore.recent(1),
    modelStore.load(process.env)
  ]);
  return print({
    status: 'enabled',
    blocklist,
    exemptions: { ips: ips.length, paths: paths.length },
    geo_blocked_countries: geo.length,
    dynamic_keywords: keywords.length,
    request_logging: { has_records: logs.length > 0 },
    model: { loaded: !!model, metadata: model?.metadata || null },
    wasm: require('../lib/wasmAdapter').getWasmStatus()
  });
}

async function operationalStats(limit = 5000) {
  const blocklistManager = require('../lib/blocklistManager');
  const requestLogStore = require('../lib/requestLogStore');
  const [blocklist, logs] = await Promise.all([blocklistManager.getStatistics(), requestLogStore.recent(limit)]);
  const statuses = {};
  const paths = {};
  let blocked = 0;
  logs.forEach(row => {
    statuses[String(row.status || 0)] = (statuses[String(row.status || 0)] || 0) + 1;
    paths[row.path || '/'] = (paths[row.path || '/'] || 0) + 1;
    if (row.blocked === true || row.blocked === 1 || String(row.blocked).toLowerCase() === 'true') blocked += 1;
  });
  return print({
    blocklist,
    requests: { total: logs.length, blocked, statuses },
    top_paths: Object.entries(paths).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([requestPath, count]) => ({ path: requestPath, count }))
  });
}

function parseManifestArgs(args = []) {
  const options = {
    framework: 'express',
    output: process.env.AIWAF_PATH_MANIFEST || '.aiwaf/paths.json',
    routes: []
  };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--framework' || arg === '-f') {
      options.framework = args[++index] || options.framework;
    } else if (arg === '--output' || arg === '-o') {
      options.output = args[++index] || options.output;
    } else if (arg === '--routes' || arg === '-r') {
      const routeFile = args[++index];
      options.routes = routeFile ? readJsonFile(routeFile) : [];
    }
  }
  return options;
}

async function diagnoseIp(ip) {
  const blocklistManager = require('../lib/blocklistManager');
  const exemptionStore = require('../lib/exemptionStore');
  const blocked = await blocklistManager.isBlocked(ip);
  const blockInfo = await blocklistManager.getBlockInfo(ip);
  const exempt = await exemptionStore.isIpExempt(ip);
  print({ ip, blocked, exempt, block_info: blockInfo });
}

function runPathShell() {
  const readline = require('readline');
  const fs = require('fs');
  const manifestPath = process.env.AIWAF_PATH_MANIFEST || '.aiwaf/paths.json';
  if (!fs.existsSync(manifestPath)) {
    console.error(`Manifest not found at ${manifestPath}. Run 'aiwaf manifest' first.`);
    return process.exit(1);
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const routes = Object.keys(manifest.routes || {});
  
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    prompt: 'aiwaf> '
  });
  
  console.log(`Loaded ${routes.length} routes from ${manifestPath}`);
  rl.prompt();
  
  rl.on('line', async (line) => {
    const args = line.trim().split(' ').filter(Boolean);
    if (!args.length) { rl.prompt(); return; }
    const cmd = args[0];
    
    if (cmd === 'exit' || cmd === 'quit') {
      rl.close();
    } else if (cmd === 'ls') {
      routes.forEach((r, i) => console.log(`[${i}] ${r}`));
    } else if (cmd === 'exempt') {
      const idx = Number(args[1]);
      const pathPrefix = !isNaN(idx) && routes[idx] ? routes[idx] : args[1];
      if (!pathPrefix) {
        console.log('Usage: exempt <index|path>');
      } else {
        const exemptionStore = require('../lib/exemptionStore');
        await exemptionStore.addPath(pathPrefix, 'manual via shell');
        console.log(`Exempted path: ${pathPrefix}`);
      }
    } else {
      console.log(`Unknown command: ${cmd}`);
      console.log(`Available commands: ls, exempt <index|path>, exit`);
    }
    rl.prompt();
  }).on('close', () => {
    console.log('Exiting shell.');
    process.exit(0);
  });
}

async function runReset(args) {
  const flags = { blocklist: false, keywords: false, exemptions: false, confirm: false };
  for (const arg of args) {
    if (arg === '--blocklist') flags.blocklist = true;
    if (arg === '--keywords') flags.keywords = true;
    if (arg === '--exemptions') flags.exemptions = true;
    if (arg === '--all') { flags.blocklist = true; flags.keywords = true; flags.exemptions = true; }
    if (arg === '--confirm') flags.confirm = true;
  }
  if (!flags.blocklist && !flags.keywords && !flags.exemptions) {
    return print({ error: 'Specify what to reset: --blocklist, --keywords, --exemptions, or --all' });
  }
  if (!flags.confirm) {
    return print({ error: 'Must pass --confirm to execute reset' });
  }

  const results = {};
  if (flags.blocklist) {
    const blocklistManager = require('../lib/blocklistManager');
    results.blocklist = await blocklistManager.clear();
  }
  if (flags.keywords) {
    const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
    results.keywords = await dynamicKeywordStore.clear();
  }
  if (flags.exemptions) {
    const exemptionStore = require('../lib/exemptionStore');
    results.exemptions = await exemptionStore.clear();
  }
  return print({ ok: true, reset: results });
}

async function main() {
  const argv = [...process.argv];
  for (const index of [2, 3]) {
    argv[index] = { blacklist: 'blocklist', whitelist: 'allowlist' }[argv[index]] || argv[index];
  }
  const [, , cmd, subcmd, ...args] = argv;

  if (!cmd || ['help', '--help', '-h'].includes(cmd)) {
    print({
      usage: 'aiwaf <command> [subcommand] [args]',
      commands: [
        'list blocklist|exemptions|geo|request-logs',
        'list dynamic-keywords',
        'list model-info',
        'list recent-blocks [hours]',
        'list top-reasons [limit]',
        'add blocklist <ip> [reason] [--duration 24h|--permanent]',
        'add ip-exemption <ip> [reason]',
        'add path-exemption <pathPrefix> [reason]',
        'add dynamic-keyword <keyword> [count]',
        'remove blocklist <ip>',
        'remove ip-exemption <ip>',
        'remove path-exemption <pathPrefix>',
        'remove dynamic-keyword <keyword>',
        'geo block <CC> [reason]',
        'geo unblock <CC>',
        'geo summary',
        'clear blocklist|request-logs',
        'clear dynamic-keywords',
        'status',
        'stats [request-limit]',
        'logs analyze [limit]',
        'blocklist migrate [--duration 24h]',
        'blocklist cleanup',
        'export [output.json]',
        'import <input.json>',
        'model info|export|import|clear [file]',
        'train',
        'manifest --framework <name> --routes <routes.json> [--output .aiwaf/paths.json]',
        'whois <domain|ip>',
        'diagnose <ip>',
        'reset [--blocklist] [--keywords] [--exemptions] [--all] --confirm',
        'pathshell'
      ]
    });
    return;
  }

  if (cmd === 'train') return runTrain();
  if (cmd === 'pathshell') return runPathShell();
  if (cmd === 'reset') return runReset([subcmd, ...args].filter(Boolean));
  if (cmd === 'status') return operationalStatus();
  if (cmd === 'stats') return operationalStats(Number(subcmd || 5000));
  if (cmd === 'export') return exportOperationalState(subcmd || 'aiwaf-export.json');
  if (cmd === 'import') return importOperationalState(subcmd);

  if (cmd === 'logs' && subcmd === 'analyze') {
    return operationalStats(Number(args[0] || 5000));
  }

  if (cmd === 'blocklist' && subcmd === 'cleanup') {
    const blocklistManager = require('../lib/blocklistManager');
    return print({ ok: true, cleaned: await blocklistManager.cleanupExpired() });
  }

  if (cmd === 'blocklist' && subcmd === 'migrate') {
    const durationIndex = args.indexOf('--duration');
    const duration = durationIndex >= 0 ? parseDuration(args[durationIndex + 1]) : null;
    const blocklistManager = require('../lib/blocklistManager');
    return print({ ok: true, ...(await blocklistManager.migrateLegacy({ duration })) });
  }

  if (cmd === 'model') {
    const modelStore = require('../lib/modelStore');
    if (subcmd === 'info') {
      const model = await modelStore.load(process.env);
      return print({ loaded: !!model, metadata: model?.metadata || null });
    }
    if (subcmd === 'export') {
      const model = await modelStore.load(process.env);
      if (!model) return print({ ok: false, error: 'model not found' });
      return print({ ok: true, output: writeJsonFile(args[0] || 'aiwaf-model.json', model) });
    }
    if (subcmd === 'import') {
      const model = readJsonFile(args[0]);
      await modelStore.save(process.env, model, model.metadata || {});
      return print({ ok: true, imported: true });
    }
    if (subcmd === 'clear') {
      return print({ ok: true, removed: await modelStore.remove(process.env) });
    }
  }

  if (cmd === 'manifest') {
    const options = parseManifestArgs([subcmd, ...args].filter(Boolean));
    const manifest = pathManifest.generateFrameworkManifest(
      options.framework,
      null,
      options.output,
      { routes: options.routes }
    );
    return print({ ok: true, output: options.output, framework: options.framework, routes: Object.keys(manifest.routes || {}).length });
  }

  if (cmd === 'list' && subcmd === 'blocklist') {
    const blocklistManager = require('../lib/blocklistManager');
    const rows = await blocklistManager.getBlockedIPs();
    return print(rows);
  }

  if (cmd === 'list' && subcmd === 'exemptions') {
    const exemptionStore = require('../lib/exemptionStore');
    const ips = await exemptionStore.listIps();
    const paths = await exemptionStore.listPaths();
    return print({ ip_exemptions: ips, path_exemptions: paths });
  }

  if (cmd === 'list' && subcmd === 'geo') {
    const geoStore = require('../lib/geoStore');
    const rows = await geoStore.listBlockedCountries();
    return print(rows);
  }

  if (cmd === 'list' && subcmd === 'request-logs') {
    const requestLogStore = require('../lib/requestLogStore');
    const limit = Number(args[0] || 100);
    const rows = await requestLogStore.recent(limit);
    return print(rows);
  }

  if (cmd === 'list' && subcmd === 'dynamic-keywords') {
    const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
    const limit = Number(args[0] || 100);
    const rows = await dynamicKeywordStore.list(limit);
    return print(rows);
  }

  if (cmd === 'list' && subcmd === 'model-info') {
    const modelStore = require('../lib/modelStore');
    const model = await modelStore.load(process.env);
    if (!model) return print({ loaded: false });
    return print({ loaded: true, metadata: model.metadata || null });
  }

  if (cmd === 'list' && subcmd === 'recent-blocks') {
    const blocklistManager = require('../lib/blocklistManager');
    return print(await blocklistManager.getRecentBlocks(Number(args[0] || 24)));
  }

  if (cmd === 'list' && subcmd === 'top-reasons') {
    const blocklistManager = require('../lib/blocklistManager');
    return print(await blocklistManager.getTopBlockedReasons(Number(args[0] || 10)));
  }

  if (cmd === 'add' && subcmd === 'ip-exemption') {
    const exemptionStore = require('../lib/exemptionStore');
    const [ip, ...reasonParts] = args;
    await exemptionStore.addIp(ip, reasonParts.join(' ') || 'manual');
    return print({ ok: true, ip });
  }

  if (cmd === 'add' && subcmd === 'blocklist') {
    const blocklistManager = require('../lib/blocklistManager');
    const [ip, ...values] = args;
    const durationIndex = values.indexOf('--duration');
    const permanent = values.includes('--permanent');
    const duration = durationIndex >= 0 ? parseDuration(values[durationIndex + 1]) : undefined;
    const reasonParts = values.filter((value, index) => value !== '--permanent'
      && value !== '--duration' && index !== durationIndex + 1);
    await blocklistManager.block(ip, reasonParts.join(' ') || 'manual', { duration, permanent });
    return print({ ok: true, ip });
  }

  if (cmd === 'add' && subcmd === 'path-exemption') {
    const exemptionStore = require('../lib/exemptionStore');
    const [pathPrefix, ...reasonParts] = args;
    await exemptionStore.addPath(pathPrefix, reasonParts.join(' ') || 'manual');
    return print({ ok: true, pathPrefix });
  }

  if (cmd === 'add' && subcmd === 'dynamic-keyword') {
    const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
    const [keyword, count] = args;
    await dynamicKeywordStore.add(keyword, Number(count || 1));
    return print({ ok: true, keyword });
  }

  if (cmd === 'remove' && subcmd === 'blocklist') {
    const blocklistManager = require('../lib/blocklistManager');
    const [ip] = args;
    const deleted = await blocklistManager.unblock(ip);
    return print({ ok: true, deleted });
  }

  if (cmd === 'remove' && subcmd === 'ip-exemption') {
    const exemptionStore = require('../lib/exemptionStore');
    const [ip] = args;
    const deleted = await exemptionStore.removeIp(ip);
    return print({ ok: true, deleted });
  }

  if (cmd === 'remove' && subcmd === 'dynamic-keyword') {
    const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
    const [keyword] = args;
    await dynamicKeywordStore.remove(keyword);
    return print({ ok: true, keyword });
  }

  if (cmd === 'remove' && subcmd === 'path-exemption') {
    const exemptionStore = require('../lib/exemptionStore');
    const [pathPrefix] = args;
    const deleted = await exemptionStore.removePath(pathPrefix);
    return print({ ok: true, deleted });
  }

  if (cmd === 'geo' && subcmd === 'block') {
    const geoStore = require('../lib/geoStore');
    const [countryCode, ...reasonParts] = args;
    await geoStore.addBlockedCountry(countryCode, reasonParts.join(' ') || 'manual');
    return print({ ok: true, countryCode });
  }

  if (cmd === 'geo' && subcmd === 'unblock') {
    const geoStore = require('../lib/geoStore');
    const [countryCode] = args;
    const deleted = await geoStore.removeBlockedCountry(countryCode);
    return print({ ok: true, deleted });
  }

  if (cmd === 'geo' && subcmd === 'summary') {
    const requestLogStore = require('../lib/requestLogStore');
    const rows = await requestLogStore.geoSummary(50);
    return print(rows);
  }

  if (cmd === 'clear' && subcmd === 'blocklist') {
    return clearBlocklist();
  }

  if (cmd === 'clear' && subcmd === 'request-logs') {
    return clearRequestLogs();
  }

  if (cmd === 'clear' && subcmd === 'dynamic-keywords') {
    const dynamicKeywordStore = require('../lib/dynamicKeywordStore');
    const cleared = await dynamicKeywordStore.clear();
    return print({ ok: true, cleared });
  }

  if (cmd === 'diagnose') {
    const [ip] = [subcmd, ...args];
    return diagnoseIp(ip);
  }

  if (cmd === 'whois') {
    const whois = require('../lib/whois');
    const [target] = [subcmd, ...args];
    const result = await whois.runWhoisLookup(target);
    process.stdout.write(`${result}\n`);
    return;
  }

  print({ error: 'unknown command', command: [cmd, subcmd, ...args].join(' ') });
  process.exitCode = 1;
}

main()
  .catch(err => {
    process.stderr.write(`${err.stack || err.message}\n`);
    process.exit(1);
  })
  .finally(async () => {
    const command = process.argv[2];
    if (!['pathshell', 'train'].includes(command)) {
      try {
        await require('../utils/db').destroy();
      } catch (err) {
        // The requested operation has already completed; cleanup is best effort.
      }
    }
  });
