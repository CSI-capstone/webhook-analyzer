/* Run the shipped renderer and event handlers with a small DOM test double. */
const fs = require("fs"),
  vm = require("vm"),
  assert = require("assert"),
  path = require("path");
const html = fs.readFileSync(
  path.join(__dirname, "../frontend/index.html"),
  "utf8",
);
const script = html.split("<script>")[1].split("</script>")[0];
const elements = new Map();
function element(id = "") {
  if (elements.has(id)) return elements.get(id);
  const e = {
    id,
    hidden: false,
    value: "",
    type: "password",
    innerHTML: "",
    textContent: "",
    disabled: false,
    files: [],
    dataset: {},
    style: {},
    listeners: {},
    classList: { add() {}, remove() {}, toggle() {} },
    querySelectorAll() {
      return [];
    },
    setAttribute(k, v) {
      this[k] = v;
    },
    addEventListener(k, f) {
      this.listeners[k] = f;
    },
    focus() {},
  };
  elements.set(id, e);
  return e;
}
const radio = { value: "false" };
const context = {
  document: {
    getElementById: element,
    querySelector() {
      return radio;
    },
    querySelectorAll() {
      return [];
    },
  },
  window: { print() {}, addEventListener() {}, scrollTo() {} },
  console,
  URL,
  Blob,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
};
vm.createContext(context);
vm.runInContext(script, context);
let checks = 0;
function check(condition, name) {
  assert(condition, name);
  checks++;
}
function run(code) {
  return vm.runInContext(code, context);
}
const attack = (status, type = "replay") => ({
  attack_type: type,
  status,
  vulnerable: status === "vulnerable",
  description: "<script>bad()</script>",
  details: ["<img src=x onerror=bad()>"],
  confidence: "LOW",
  variant: "expired_timestamp",
  status_code: 200,
});
const uncertain = context.renderDAST(
  ["observed", "inconclusive", "skipped"].map((s) => attack(s)),
);
check(
  !uncertain.includes("dast-item safe"),
  "Uncertain results never rendered as rejected",
);
check(
  (uncertain.match(/dast-item pending/g) || []).length === 3,
  "All uncertain statuses preserved",
);
check(!uncertain.includes("<script>bad()"), "Descriptions escaped");
check(
  uncertain.includes("&lt;script&gt;bad()"),
  "Escaped descriptions visible",
);
check(
  uncertain.includes("&lt;img src=x onerror=bad()&gt;"),
  "Evidence escaped",
);
check(
  context.gradeClass("N/A — 추가 확인 필요") === "grade-unknown",
  "N/A neutral",
);
check(
  context.groupStatus([attack("rejected"), attack("skipped")]) ===
    "inconclusive",
  "Mixed rejection/skipped not clean",
);
check(
  context.groupStatus([attack("rejected"), attack("vulnerable")]) ===
    "vulnerable",
  "Confirmed evidence represented",
);
check(
  context.attackStatus({ status: "constructor", vulnerable: false }) ===
    "inconclusive",
  "Unknown status controlled",
);
const report = {
  target_file: "<script>file()</script>.py",
  overall_grade: "N/A — 추가 확인 필요",
  endpoints: [],
  dast_ran: true,
};
const rendered = context.renderReport(report);
check(rendered.includes("grade-unknown"), "Unknown report grade");
check(rendered.includes("&lt;script&gt;file()"), "Filename escaped");
check(
  rendered.includes("분석된 엔드포인트가 없습니다"),
  "Empty endpoint state",
);
check(!rendered.includes("undefined"), "Missing fields handled");
check(
  context.docLink({ title: "test", url: "javascript:alert(1)" }) === "",
  "Unsafe document URL rejected",
);
check(
  context
    .docLink({ title: "<x>", url: "https://docs.python.org/" })
    .includes("&lt;x&gt;"),
  "Document title escaped",
);
const finding = {
  severity: "HIGH",
  rule_id: "WHSEC-002",
  rule_name: "일반 비교",
  lineno: 4,
  filepath: "test.py",
  message: "<danger>",
  fix_snippet: "if x != expected:\n    reject()",
  source_context: {
    start_line: 3,
    lines: [
      "def hook():",
      "    if signature == expected:",
      '        return "<ok>"',
    ],
  },
};
const source = context.renderSAST([finding], 0, "generic");
check(
  source.includes("code-line marked"),
  "Actual detected source line highlighted",
);
check(source.includes("&lt;ok&gt;"), "Source code escaped");
check(source.includes("L4"), "Actual line number retained");
const fixed = context.renderFixes([finding], 0, "generic");
check(fixed.includes("data-copy="), "Fix copy control exists");
check(fixed.includes("성공·거부 분기"), "Fix application scope stated");
check(
  !context
    .renderEndpoint(
      { path: "/hook", sast_findings: [], dast_results: [], tier: "Tier 2" },
      0,
    )
    .includes("Tier 2 · HTTP 관측"),
  "SAST-only does not claim dynamic observations",
);
check(
  context
    .renderEndpoint(
      {
        path: "/hook",
        overall_severity: 'HIGH" onclick="bad()',
        sast_findings: [],
        dast_results: [],
      },
      0,
    )
    .includes("severity INFO"),
  "Severity class injection blocked",
);
run(
  "ui.report={endpoints:[{path:'/hook/one',sast_findings:[],dast_results:[]},{path:'/hook/two',sast_findings:[],dast_results:[]}]};ui.query='two'",
);
const filtered = context.renderEndpointList(run("ui.report"));
check(
  filtered.includes("/hook/two") && !filtered.includes("/hook/one"),
  "Endpoint search filters actual paths",
);
run("applyEndpointFilter()");
check(run("ui.endpoint") === 1, "Filter selects matching endpoint");
run("ui.query='no-match';applyEndpointFilter()");
check(
  element("endpoint-detail").innerHTML.includes("필터에 맞는 결과가 없습니다"),
  "No-match filter clears stale details",
);
const data = {
  ...report,
  target_file: "sample.py",
  endpoints: [
    {
      path: "/hook",
      overall_severity: "HIGH",
      sast_findings: [finding],
      dast_results: [attack("observed")],
    },
  ],
};
const printed = context.buildPrintReport(data);
check(
  printed.includes("修正") === false && printed.includes("수정 가이드"),
  "Print contains guidance",
);
check(printed.includes("expired_timestamp"), "Print includes dynamic evidence");
const form = new Map([
  ["webhook_url", "file:///tmp/source"],
  ["state_create", ""],
  ["state_query", ""],
]);
check(
  context.validateDynamic(form).includes("HTTP(S)"),
  "URL protocol validation",
);
form.set("webhook_url", "http://127.0.0.1:8000");
form.set("state_create", "/orders");
check(
  context.validateDynamic(form).includes("함께"),
  "State path pair validation",
);
form.set("state_query", "/orders/{id}");
check(context.validateDynamic(form) === "", "Valid config accepted");
radio.value = "true";
check(
  context.validateDynamic(new Map()) === "",
  "SAST-only bypasses DAST input",
);
console.log(
  `PASS: ${checks} frontend checks (status semantics, escaping, source evidence, filters, guides, print, inputs)`,
);
