"use strict";

const config = JSON.parse(document.getElementById("demo-config").textContent);
const $ = (id) => document.getElementById(id);
const escapeHTML = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"}[char]));
const won = (value) => Number(value || 0).toLocaleString("ko-KR") + "원";
const isDone = (order) => ["paid", "processed"].includes(order.status);
const stateName = (value) => ({pending: config.platform === "slack" ? "알림 대기" : "결제 대기", paid:"결제 완료", processed:"알림 처리 완료"}[value] || value);
const scenarioName = (value) => ({normal:"정상 알림", expired:"만료 알림", invalid_signature:"잘못된 서명", missing_signature:"서명 누락"}[value] || value);
let snapshot = null;
let category = "전체";
let orderFilter = "all";
let paymentOrder = null;
let evidenceId = null;
let busy = false;
let toastTimer = null;
const cart = new Map();

function artwork(product, className = "") {
  const allowed = ["hoodie", "mug", "bag", "pen", "notebook", "box"];
  const kind = allowed.includes(product.kind) ? product.kind : "box";
  const tone = /^#[0-9a-f]{6}$/i.test(product.tone || "") ? product.tone : "#71869a";
  return `<svg class="${className}" style="--product-tone:${tone}" viewBox="0 0 300 240" aria-hidden="true"><use href="/demo-assets/products.svg#${kind}"/></svg>`;
}

function toast(message) {
  $("toast").textContent = message;
  $("toast").classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => $("toast").classList.remove("show"), 3600);
}

async function api(path, data) {
  const options = data === undefined ? {cache:"no-store"} : {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(data)};
  const response = await fetch(path, options);
  const result = await response.json();
  if (!response.ok) {
    const detail = typeof result.detail === "string" ? result.detail : "요청을 처리하지 못했습니다.";
    throw new Error(detail);
  }
  return result;
}

function initBrand() {
  document.body.classList.add("theme-" + config.theme);
  document.title = config.name + " · HookLens 시연 스토어";
  $("brandName").textContent = config.name;
  $("brandMark").textContent = config.name.charAt(0);
  $("heroEyebrow").textContent = config.eyebrow;
  $("heroTitle").textContent = config.title;
  $("heroDescription").textContent = config.description;
  $("heroBadge").textContent = config.badge;
  $("collectionTitle").textContent = config.collection;
  $("storyBrand").textContent = config.name;
  $("footerBrand").textContent = config.name;
  if (config.platform === "slack") {
    $("teamFeed").hidden = false;
    $("processedLabel").textContent = "알림 처리 완료";
    $("orderHelp").textContent = "모의 결제 후 Slack 형식의 메시지를 수신합니다. 결제 상태와 알림 처리 상태를 구분해서 확인합니다.";
    $("consoleIntro").textContent = "Slack 서명은 결제 승인용이 아니라 메시지 수신 검증용입니다. 여기서는 주문 알림의 정상·만료·변조 요청을 실제 수신 핸들러로 보냅니다.";
  }
}

function renderProducts() {
  const categories = ["전체", ...new Set(snapshot.products.map((product) => product.category))];
  $("categoryFilters").innerHTML = categories.map((name) => `<button type="button" data-category="${escapeHTML(name)}" class="${name === category ? "active" : ""}">${escapeHTML(name)}</button>`).join("");
  const products = snapshot.products.filter((product) => category === "전체" || product.category === category);
  $("productCount").textContent = products.length + "개 상품";
  $("productGrid").innerHTML = products.map((product) => `<article class="product-card">
    <div class="product-picture">${product.tag ? `<span class="product-tag">${escapeHTML(product.tag)}</span>` : ""}${artwork(product)}</div>
    <p class="product-category">${escapeHTML(product.category)}</p><h3 class="product-name">${escapeHTML(product.name)}</h3>
    <div class="product-bottom"><strong class="product-price">${won(product.price)}</strong><button class="add-to-cart" type="button" data-add="${escapeHTML(product.id)}">담기 ＋</button></div><p class="product-stock">시연 재고 ${product.stock}개 · 로컬 주문</p></article>`).join("");
}

function cartRows() {
  if (!snapshot) return [];
  return [...cart.entries()].map(([id, quantity]) => ({...snapshot.products.find((product) => product.id === id), quantity})).filter((product) => product.id);
}

function renderCart() {
  const rows = cartRows();
  const count = rows.reduce((sum, row) => sum + row.quantity, 0);
  $("cartCount").textContent = count;
  const delivery = document.querySelector('input[name="delivery"]:checked').value;
  $("addressLabel").hidden = delivery !== "shipping";
  const subtotal = rows.reduce((sum, row) => sum + row.price * row.quantity, 0);
  const shipping = delivery === "shipping" && subtotal > 0 && subtotal < 50000 ? 3000 : 0;
  $("cartSubtotal").textContent = won(subtotal);
  $("cartShipping").textContent = won(shipping);
  $("cartTotal").textContent = won(subtotal + shipping);
  $("createOrderButton").disabled = rows.length === 0 || busy;
  $("cartItems").innerHTML = rows.length ? rows.map((row) => `<div class="cart-item"><div class="cart-item-art">${artwork(row)}</div><div class="cart-item-info"><strong>${escapeHTML(row.name)}</strong><span class="cart-item-price">${won(row.price)}</span><div class="quantity-control"><button data-quantity="${escapeHTML(row.id)}" data-delta="-1" type="button" aria-label="${escapeHTML(row.name)} 수량 줄이기">−</button><span>${row.quantity}</span><button data-quantity="${escapeHTML(row.id)}" data-delta="1" type="button" aria-label="${escapeHTML(row.name)} 수량 늘리기">＋</button></div></div><button data-remove="${escapeHTML(row.id)}" class="remove-item" type="button" aria-label="${escapeHTML(row.name)} 삭제">×</button></div>`).join("") : '<div class="empty-state"><div class="empty-icon">＋</div><h3>장바구니가 비어 있어요.</h3><p>마음에 드는 상품을 먼저 담아 주세요.</p></div>';
}

function renderOrders() {
  const query = $("orderSearch").value.trim().toLowerCase();
  const rows = snapshot.orders.filter((order) => (orderFilter === "all" || (orderFilter === "done" ? isDone(order) : !isDone(order)))
    && (!query || [order.order_id, order.product_name || "", order.customer?.name || ""].join(" ").toLowerCase().includes(query)));
  $("statTotal").textContent = snapshot.stats.total;
  $("statProcessed").textContent = snapshot.stats.processed;
  $("statPending").textContent = snapshot.stats.pending;
  $("orderList").innerHTML = rows.length ? rows.map((order) => {
    const source = order.source === "storefront" ? "스토어 주문" : order.source === "security_demo" ? "시연 관리 시험 주문" : "HookLens / API 시험 주문";
    const date = order.created_at ? new Date(order.created_at).toLocaleString("ko-KR", {month:"2-digit", day:"2-digit", hour:"2-digit", minute:"2-digit"}) : "실시간 수신 상태";
    const item = order.items?.[0] || {kind:"box"};
    const title = order.product_name || "웹훅 처리 확인용 시험 주문";
    const canPay = !isDone(order) && ["storefront", "security_demo"].includes(order.source);
    const approved = order.provider_status === "approved";
    const meta = order.items ? `${order.items.reduce((sum, line) => sum + line.quantity, 0)}개 상품 · ${won(order.amount)} · ${order.delivery === "shipping" ? "모의 택배" : "직접 수령"}` : "분석기가 생성한 시험 상태";
    const slackPayment = config.platform === "slack" ? `<span class="status-badge ${order.payment_status === "paid" ? "done" : "neutral"}">${order.payment_status === "paid" ? "모의 결제 완료" : "결제 미진행"}</span> ` : "";
    return `<article class="order-card"><div class="order-card-header"><span><strong>#${escapeHTML(order.order_id.slice(0, 10))}</strong> · ${source}</span><span>${escapeHTML(date)}</span></div><div class="order-card-main"><div class="order-art">${artwork(item)}</div><div><p class="order-title">${escapeHTML(title)}</p><p class="order-meta">${escapeHTML(meta)}${order.customer ? "<br>" + escapeHTML(order.customer.name) : ""}</p></div><div class="order-card-right">${slackPayment}<span class="status-badge ${isDone(order) ? "done" : ""}">${escapeHTML(stateName(order.status))}</span>${canPay ? `<button class="order-pay" type="button" data-pay="${escapeHTML(order.order_id)}">모의 결제하기</button>` : ""}</div></div><div class="order-steps"><span class="active">주문 생성</span><span class="${approved ? "active" : ""}">모의 결제사 승인</span><span class="${isDone(order) ? "active" : ""}">${config.platform === "slack" ? "주문 알림 처리" : "결제 알림 수신"}</span></div></article>`;
  }).join("") : `<div class="empty-state"><div class="empty-icon">▤</div><h3>${query || orderFilter !== "all" ? "조건에 맞는 주문이 없어요." : "아직 주문한 상품이 없어요."}</h3><p>${query || orderFilter !== "all" ? "검색어 또는 필터를 바꿔 보세요." : "상품을 장바구니에 담고 주문서를 작성해 보세요."}</p></div>`;
  renderConsoleSelects();
}

function renderConsoleSelects() {
  const priorPath = $("targetRoute").value;
  $("targetRoute").innerHTML = snapshot.paths.map((path, index) => `<option value="${escapeHTML(path)}">${index === 0 ? "기본 수신 경로" : "보완 경로"} · ${escapeHTML(path)}</option>`).join("");
  if (snapshot.paths.includes(priorPath)) $("targetRoute").value = priorPath;
  const priorOrder = $("targetOrder").value;
  const eligible = snapshot.orders.filter((order) => order.status === "pending" && ["storefront", "security_demo"].includes(order.source));
  $("targetOrder").innerHTML = eligible.length ? eligible.map((order) => `<option value="${escapeHTML(order.order_id)}">#${escapeHTML(order.order_id.slice(0, 8))} · ${escapeHTML(order.product_name || "시험 주문")}</option>`).join("") : '<option value="">새 시험 주문을 사용해 주세요.</option>';
  if (eligible.some((order) => order.order_id === priorOrder)) $("targetOrder").value = priorOrder;
  $("targetOrder").disabled = $("newTestOrder").checked;
}

function renderEvidence(log) {
  if (!log) {
    $("evidence").className = "evidence empty-evidence";
    $("evidence").textContent = "시험 요청을 보내면 HTTP 응답과 처리 전후 상태가 여기에 표시됩니다.";
    $("requestPreview").textContent = "아직 보낸 요청이 없습니다.";
    return;
  }
  const accepted = log.http_status >= 200 && log.http_status < 300;
  let description = accepted ? "수신 핸들러가 요청을 수락했습니다." : "수신 핸들러가 요청을 거부했습니다. 주문 상태를 함께 확인하세요.";
  if (log.scenario === "expired" && log.state_changed) description = "만료된 시간값과 유효한 서명을 가진 요청이 처리됐습니다. 시간 만료 검사 누락을 확인할 수 있습니다.";
  if (log.scenario === "expired" && !accepted) description = "만료 요청이 거부됐습니다. Stripe·Slack 보완 경로와 기본 경로를 비교해 보세요.";
  if (config.platform === "slack") description += " 이 결과는 메시지 처리 상태이며 결제 승인 결과와 구분합니다.";
  $("evidence").className = "evidence";
  $("evidence").innerHTML = `<div class="evidence-top"><span class="evidence-title">${escapeHTML(scenarioName(log.scenario))}</span><span class="http-code ${accepted ? "accepted" : "rejected"}">HTTP ${log.http_status}</span><span class="muted">#${escapeHTML(log.order_id.slice(0, 8))}</span></div><div class="evidence-change"><span>${escapeHTML(stateName(log.before))}</span><span class="arrow">→</span><span>${escapeHTML(stateName(log.after))}</span></div><p class="evidence-description">${escapeHTML(description)}</p>`;
  $("requestPreview").textContent = JSON.stringify({수신경로:log.path, 시나리오:scenarioName(log.scenario), 요청헤더:log.request_headers, 요청본문:log.request_body, HTTP응답:log.http_status, 응답본문:log.response, 상태변경:log.state_changed, 처리전:log.before, 처리후:log.after}, null, 2);
}

function renderHistory() {
  $("deliveryHistory").innerHTML = snapshot.logs.length ? snapshot.logs.slice(0, 12).map((log) => `<div class="delivery-row"><span>${new Date(log.at).toLocaleTimeString("ko-KR", {hour12:false})}</span><span class="delivery-name">${escapeHTML(scenarioName(log.scenario))}<small>${escapeHTML(log.path)} · #${escapeHTML(log.order_id.slice(0, 8))}</small></span><span class="http-code ${log.http_status < 300 ? "accepted" : "rejected"}">HTTP ${log.http_status}</span><span class="delivery-result">${escapeHTML(stateName(log.before))} → ${escapeHTML(stateName(log.after))}</span></div>`).join("") : '<p class="muted">현재 화면에서 전송한 요청이 없습니다.</p>';
  renderEvidence(snapshot.logs.find((log) => log.id === evidenceId) || snapshot.logs[0]);
  if (config.platform === "slack") {
    $("teamMessages").innerHTML = snapshot.logs.length ? snapshot.logs.slice(0, 6).map((log) => `<div class="team-message"><span class="message-avatar">B</span><div class="message-body"><strong>모의 주문 알림 봇</strong><time>${new Date(log.at).toLocaleTimeString("ko-KR", {hour:"2-digit", minute:"2-digit"})}</time><p>${escapeHTML(log.request_body.event?.text || "팀 주문 알림")}</p><div class="message-result">${log.http_status >= 200 && log.http_status < 300 ? "수신 처리됨" : "수신 거부됨"} · ${escapeHTML(scenarioName(log.scenario))} · HTTP ${log.http_status}</div></div></div>`).join("") : '<div class="team-message"><span class="message-avatar">#</span><div class="message-body"><strong>팀 주문 채널에 오신 것을 환영합니다.</strong><p>모의 결제를 하거나 시연 요청을 보내면 실제 수신 결과가 여기에 표시됩니다.</p></div></div>';
  }
}

async function refresh(initial = false) {
  snapshot = await api("/demo/state");
  if (initial) renderProducts();
  renderOrders();
  renderHistory();
}

function openPayment(order) {
  paymentOrder = order;
  $("paymentProduct").textContent = order.product_name;
  $("paymentOrderId").textContent = "주문번호 #" + order.order_id.slice(0, 12);
  $("paymentAmount").textContent = won(order.amount);
  $("paymentError").textContent = "";
  $("paymentDialog").showModal();
}

function setBusy(value) {
  busy = value;
  document.querySelectorAll('[data-scenario], #approvePayment').forEach((button) => { button.disabled = value; });
  renderCart();
}

$("openCart").addEventListener("click", () => { renderCart(); $("checkoutError").textContent = ""; $("checkoutDialog").showModal(); });
document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => $(button.dataset.close).close()));
$("categoryFilters").addEventListener("click", (event) => { const button = event.target.closest("[data-category]"); if (button) { category = button.dataset.category; renderProducts(); } });
$("productGrid").addEventListener("click", (event) => {
  const button = event.target.closest("[data-add]");
  if (!button) return;
  const product = snapshot.products.find((row) => row.id === button.dataset.add);
  const quantity = (cart.get(product.id) || 0) + 1;
  if (quantity > Math.min(product.stock, 20)) return toast("선택할 수 있는 수량을 초과했습니다.");
  cart.set(product.id, quantity); renderCart(); toast(product.name + "을(를) 장바구니에 담았어요.");
});
$("cartItems").addEventListener("click", (event) => {
  const remove = event.target.closest("[data-remove]");
  const change = event.target.closest("[data-quantity]");
  if (remove) cart.delete(remove.dataset.remove);
  if (change) {
    const product = snapshot.products.find((row) => row.id === change.dataset.quantity);
    const quantity = (cart.get(product.id) || 0) + Number(change.dataset.delta);
    if (quantity <= 0) cart.delete(product.id);
    else if (quantity <= Math.min(product.stock, 20)) cart.set(product.id, quantity);
  }
  renderCart();
});
document.querySelectorAll('input[name="delivery"]').forEach((input) => input.addEventListener("change", renderCart));
$("checkoutForm").addEventListener("submit", async (event) => {
  event.preventDefault(); if (busy) return;
  $("checkoutError").textContent = "";
  setBusy(true);
  try {
    const order = await api("/demo/order", {items:cartRows().map((row) => ({id:row.id, quantity:row.quantity})), delivery:document.querySelector('input[name="delivery"]:checked').value,
      customer:{name:$("buyerName").value, email:$("buyerEmail").value, address:$("buyerAddress").value}});
    cart.clear(); renderCart(); $("checkoutDialog").close(); await refresh(); openPayment(order);
  } catch (error) { $("checkoutError").textContent = error.message; }
  finally { setBusy(false); }
});
$("paymentForm").addEventListener("submit", async (event) => {
  event.preventDefault(); if (busy || !paymentOrder) return;
  setBusy(true); $("paymentError").textContent = "";
  try {
    const result = await api("/demo/pay", {order_id:paymentOrder.order_id, method:document.querySelector('input[name="method"]:checked').value});
    evidenceId = result.delivery.id; $("paymentDialog").close(); await refresh();
    $("orders").scrollIntoView({behavior:"smooth", block:"start"});
    toast(result.delivery.state_changed ? "모의 결제와 수신 처리를 확인했어요." : "알림 응답을 확인해 주세요. HTTP " + result.delivery.http_status);
  } catch (error) { $("paymentError").textContent = error.message; }
  finally { setBusy(false); }
});
$("orderList").addEventListener("click", (event) => { const button = event.target.closest("[data-pay]"); if (button) openPayment(snapshot.orders.find((order) => order.order_id === button.dataset.pay)); });
$("orderFilters").addEventListener("click", (event) => { const button = event.target.closest("[data-order-filter]"); if (!button) return; orderFilter = button.dataset.orderFilter; $("orderFilters").querySelectorAll("button").forEach((row) => row.classList.toggle("active", row === button)); renderOrders(); });
$("orderSearch").addEventListener("input", renderOrders);
$("refreshOrders").addEventListener("click", () => refresh().then(() => toast("최신 주문 상태를 불러왔어요.")).catch((error) => toast(error.message)));
$("newTestOrder").addEventListener("change", renderConsoleSelects);
$("openDemo").addEventListener("click", () => { $("demoPanel").open = true; });
document.querySelectorAll("[data-scenario]").forEach((button) => button.addEventListener("click", async () => {
  if (busy) return;
  if (!$("newTestOrder").checked && !$("targetOrder").value) return toast("새 시험 주문 사용을 선택하거나 대기 주문을 골라 주세요.");
  setBusy(true);
  try {
    const result = await api("/demo/send", {scenario:button.dataset.scenario, new_order:$("newTestOrder").checked, order_id:$("targetOrder").value, path:$("targetRoute").value});
    evidenceId = result.delivery.id; await refresh(); toast(scenarioName(button.dataset.scenario) + " · HTTP " + result.delivery.http_status);
  } catch (error) { toast(error.message); }
  finally { setBusy(false); }
}));
$("resetDemo").addEventListener("click", async () => {
  if (busy || !window.confirm("이 서버의 시연 주문과 요청 기록을 모두 초기화할까요?")) return;
  try { await api("/demo/reset", {}); evidenceId = null; paymentOrder = null; await refresh(); toast("시연 데이터를 초기화했어요."); }
  catch (error) { toast(error.message); }
});

initBrand();
refresh(true).catch((error) => { $("productGrid").innerHTML = `<div class="empty-state"><h3>서버 연결을 확인해 주세요.</h3><p>${escapeHTML(error.message)}</p></div>`; toast(error.message); });
setInterval(() => { if (!busy && !document.hidden) refresh().catch(() => {}); }, 2500);
